/*
**  Copyright (c) 2010 The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dkim_atps_c_id[] = "@(#)$Id$";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>

/* libopendkim includes */
#include "dkim.h"
#include "dkim-internal.h"
#include "dkim-types.h"
#include "util.h"

/* openssl includes */
#include <openssl/sha.h>

/* prototypes */
extern void dkim_error __P((DKIM *, const char *, ...));

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */
#ifndef T_RRSIG
# define T_RRSIG		46
#endif /* ! T_RRSIG */

#define	DKIM_ATPS_QUERYLENGTH	32

/*
**  DKIM_ATPS_CHECK -- check for Authorized Third Party Signing
**
**  Parameters:
**  	dkim -- DKIM message handle
**  	sig -- signature information handle
**  	timeout -- timeout (can be NULL)
**  	res -- ATPS result code
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_atps_check(DKIM *dkim, DKIM_SIGINFO *sig, struct timeval *timeout,
                dkim_atps_t *res)
{
	int status;
	int qdcount;
	int ancount;
	int class;
	int type;
	int error;
	int n;
	size_t buflen;
	size_t anslen;
	DKIM_LIB *lib;
	u_char *fdomain;
	u_char *sdomain;
	u_char *txtfound = NULL;
	void *qh;
	u_char *cp;
	u_char *eom;
        SHA_CTX ctx;
	struct timeval to;
	HEADER hdr;
	u_char ansbuf[MAXPACKET];
	u_char digest[SHA_DIGEST_LENGTH];
	u_char b32[DKIM_ATPS_QUERYLENGTH + 1];
	u_char query[DKIM_MAXHOSTNAMELEN + 1];

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(res != NULL);

#ifdef _FFR_ATPS

	sdomain = dkim_sig_getdomain(sig);
	fdomain = dkim_getdomain(dkim);
	lib = dkim->dkim_libhandle;

	if (sdomain == NULL || fdomain == NULL)
		return DKIM_STAT_INVALID;

	/* construct a SHA1 hash of the signing domain */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, sdomain, strlen(sdomain));
	SHA1_Final(digest, &ctx);

	/* base32-encode the hash */
	memset(b32, '\0', sizeof b32);
	buflen = sizeof b32;
	if (dkim_base32_encode(b32, &buflen,
	                       digest, sizeof digest) != DKIM_ATPS_QUERYLENGTH)
		return DKIM_STAT_INTERNAL;

	/* form the query */
	snprintf(query, sizeof query, "%s._atps.%s", b32, fdomain);

	/* XXX -- add QUERY_CACHE support here */

	/* send it */
	anslen = sizeof ansbuf;
	status = lib->dkiml_dns_start(lib->dkiml_dns_service, T_TXT,
	                              query, ansbuf, anslen, &qh);
	if (status != DKIM_DNS_SUCCESS)
	{
		*res = DKIM_ATPS_UNKNOWN;
		return DKIM_STAT_CANTVRFY;
	}

	/* wait for the reply */
	to.tv_sec = dkim->dkim_timeout;
	to.tv_usec = 0;
	status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service, qh,
	                                  timeout == NULL ? &to : timeout,
	                                  &anslen, &error, NULL);
	(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, qh);

	if (status != DKIM_DNS_SUCCESS)
	{
		*res = DKIM_ATPS_UNKNOWN;
		return DKIM_STAT_CANTVRFY;
	}

	/* decode the reply */
	memcpy(&hdr, ansbuf, sizeof hdr);
	cp = (u_char *) &ansbuf + HFIXEDSZ;
	eom = (u_char *) &ansbuf + anslen;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		(void) dn_expand((unsigned char *) &ansbuf, eom, cp,
		                 (char *) query, sizeof query);
 
		if ((n = dn_skipname(cp, eom)) < 0)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			*res = DKIM_ATPS_UNKNOWN;
			return DKIM_STAT_CANTVRFY;
		}
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			*res = DKIM_ATPS_UNKNOWN;
			return DKIM_STAT_CANTVRFY;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_TXT || class != C_IN)
	{
		dkim_error(dkim, "`%s' unexpected reply type/class", query);
		*res = DKIM_ATPS_UNKNOWN;
		return DKIM_STAT_CANTVRFY;
	}

	if (hdr.rcode == NXDOMAIN)
	{
		*res = DKIM_ATPS_NOTFOUND;
		return DKIM_STAT_OK;
	}

	/* if truncated, we can't do it */
	if (dkim_check_dns_reply(ansbuf, anslen, C_IN, T_TXT) == 1)
	{
		dkim_error(dkim, "`%s' reply truncated", query);
		*res = DKIM_ATPS_UNKNOWN;
		return DKIM_STAT_CANTVRFY;
	}

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
	{
		*res = DKIM_ATPS_NOTFOUND;
		return DKIM_STAT_OK;
	}

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) &ansbuf, eom, cp,
		                   (RES_UNC_T) query, sizeof query)) < 0)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			*res = DKIM_ATPS_UNKNOWN;
			return DKIM_STAT_CANTVRFY;
		}
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			*res = DKIM_ATPS_UNKNOWN;
			return DKIM_STAT_CANTVRFY;
		}

		GETSHORT(type, cp);
		GETSHORT(class, cp);

#ifdef QUERY_CACHE
		/* get the TTL */
		GETLONG(ttl, cp);
#else /* QUERY_CACHE */
		/* skip the TTL */
		cp += INT32SZ;
#endif /* QUERY_CACHE */

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			char chost[DKIM_MAXHOSTNAMELEN + 1];

			n = dn_expand((u_char *) &ansbuf, eom, cp,
			              chost, DKIM_MAXHOSTNAMELEN);
			cp += n;
			continue;
		}
		else if (type == T_RRSIG)
		{
			/* get payload length */
			if (cp + INT16SZ > eom)
			{
				dkim_error(dkim, "`%s' reply corrupt", query);
				*res = DKIM_ATPS_UNKNOWN;
				return DKIM_STAT_CANTVRFY;
			}
			GETSHORT(n, cp);

			cp += n;

			continue;
		}
		else if (type != T_TXT)
		{
			dkim_error(dkim, "`%s' reply was unexpected type %d",
			           query, type);
			*res = DKIM_ATPS_UNKNOWN;
			return DKIM_STAT_CANTVRFY;
		}

		if (txtfound != NULL)
		{
			dkim_error(dkim, "multiple DNS replies for `%s'",
			           query);
			*res = DKIM_ATPS_UNKNOWN;
			return DKIM_STAT_MULTIDNSREPLY;
		}

		/* remember where this one started */
		txtfound = cp;

		/* get payload length */
		if (cp + INT16SZ > eom)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			*res = DKIM_ATPS_UNKNOWN;
			return DKIM_STAT_CANTVRFY;
		}
		GETSHORT(n, cp);

		/* move forward for now */
		cp += n;
	}

	/* if ancount went below 0, there were no good records */
	if (txtfound == NULL)
	{
		dkim_error(dkim, "`%s' reply was unresolved CNAME", query);
		*res = DKIM_ATPS_UNKNOWN;
		return DKIM_STAT_CANTVRFY;
	}

	/* come back to the one we found */
	cp = txtfound;

	/* get payload length */
	if (cp + INT16SZ > eom)
	{
		dkim_error(dkim, "`%s' reply corrupt", query);
		*res = DKIM_ATPS_UNKNOWN;
		return DKIM_STAT_CANTVRFY;
	}
	GETSHORT(n, cp);

	if (cp + n > eom)
	{
		dkim_error(dkim, "`%s' reply corrupt", query);
		*res = DKIM_ATPS_UNKNOWN;
		return DKIM_STAT_CANTVRFY;
	}

	/* XXX -- we have a payload; that's enough for now */

	*res = DKIM_ATPS_FOUND;
	return DKIM_STAT_OK;

#else /* ! _FFR_ATPS */

	return DKIM_STAT_NOTIMPLEMENT;

#endif /* ! _FFR_ATPS */
}
