/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: dkim-rep.c,v 1.5 2009/10/22 19:35:00 cm-msk Exp $
*/

#ifndef lint
static char dkim_rep_c_id[] = "@(#)$Id: dkim-rep.c,v 1.5 2009/10/22 19:35:00 cm-msk Exp $";
#endif /* !lint */

#ifdef _FFR_DKIM_REPUTATION

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

#ifdef USE_ARLIB
/* libar includes */
# include <ar.h>
#else /* USE_ARLIB */
# include <netdb.h>
#endif /* USE_ARLIB */

/* openssl includes */
#include <openssl/md5.h>

/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-types.h"
#include "util.h"

/* prototypes */
extern void dkim_error __P((DKIM *, const char *, ...));

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

/*
**  DKIM_MD5_TO_STRING -- convert an MD5 digest to printable hex
**
**  Parameters:
**  	md5 -- MD5 digest
**  	str -- destination string
**  	len -- bytes available at "str"
**
**  Return value:
**  	-1 -- not enough room in "str" for output
**  	otherwise -- number of bytes written to "str", not including a
**  	             terminating NULL
*/

static int
dkim_md5_to_string(MD5_CTX *md5, unsigned char *str, size_t len)
{
	int c;
	int out = 0;
	unsigned char *cvt;
	unsigned char digest[MD5_DIGEST_LENGTH];

	assert(md5 != NULL);
	assert(str != NULL);

	if (len < 2 * MD5_DIGEST_LENGTH + 1)
		return -1;

	MD5_Final(digest, md5);

	for (cvt = str, c = 0; c < MD5_DIGEST_LENGTH; c++)
	{
		snprintf((char *) cvt, len, "%02x", digest[c]);
		cvt += 2;
		out += 2;
		len -= out;
	}

	return out;
}

/*
**  DKIM_STRING_EMPTY -- determine if a string is empty or not
**
**  Parameters:
**  	str -- string to analyze
**
**  Return value:
**  	TRUE iff "str" contained no non-whitespace characters
*/

static bool
dkim_string_empty(char *str)
{
	char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (!isascii(*p) || !isspace(*p))
			return FALSE;
	}

	return TRUE;
}

/*
**  DKIM_REPUTATION -- query DKIM reputation
**
**  Parameters:
**  	dkim -- DKIM handle
**  	user -- local-part from the From: header field
**  	domain -- domain from the From: header field
**  	signdomain -- domain attaching the signature
**  	qroot -- query root
**  	rep -- pointer to an int where the reputation should be returned
**
**  Return value:
**  	1 -- reputation returned
**  	0 -- no reputation data available
**  	-1 -- data error
**  	-2 -- internal error
**
**  Notes:
**  	DNS interface documented at http://www.dkim-reputation.org
*/

int
dkim_reputation(DKIM *dkim, u_char *user, u_char *domain, char *signdomain,
                char *qroot, int *rep)
{
	int c;
	int out;
	size_t anslen;
	int qdcount;
	int ancount;
	int n;
	int type;
	int class;
	int status;
#ifdef QUERY_CACHE
	uint32_t ttl;
#endif /* QUERY_CACHE */
#ifdef USE_ARLIB
	int error;
	AR_LIB ar;
	AR_QUERY q;
	DKIM_LIB *lib;
#endif /* USE_ARLIB */
	char *ctx;
	char *eq;
	char *p;
	char *e;
	char *eob;
	unsigned char *cp;
	unsigned char *eom;
	MD5_CTX md5_user;
	MD5_CTX md5_domain;
	MD5_CTX md5_signdomain;
	HEADER hdr;
#ifdef USE_ARLIB
	struct timeval timeout;
#endif /* USE_ARLIB */
	unsigned char md5_user_str[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char md5_domain_str[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char md5_signdomain_str[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char ansbuf[MAXPACKET];
	char query[DKIM_MAXHOSTNAMELEN + 1];
	char qname[DKIM_MAXHOSTNAMELEN + 1];
	char buf[BUFRSZ + 1];

	assert(dkim != NULL);
	assert(user != NULL);
	assert(domain != NULL);
	assert(signdomain != NULL);
	assert(qroot != NULL);
	assert(rep != NULL);

	/* hash the values */
	memset(md5_user_str, '\0', sizeof md5_user_str);
	MD5_Init(&md5_user);
	MD5_Update(&md5_user, (void *) user, strlen((char *) user));
	(void) dkim_md5_to_string(&md5_user, md5_user_str,
	                          sizeof md5_user_str);

	memset(md5_domain_str, '\0', sizeof md5_domain_str);
	MD5_Init(&md5_domain);
	MD5_Update(&md5_domain, (void *) domain, strlen((char *) domain));
	(void) dkim_md5_to_string(&md5_domain, md5_domain_str,
	                          sizeof md5_domain_str);

	memset(md5_signdomain_str, '\0', sizeof md5_signdomain_str);
	MD5_Init(&md5_signdomain);
	MD5_Update(&md5_signdomain, (void *) signdomain, strlen(signdomain));
	(void) dkim_md5_to_string(&md5_signdomain, md5_signdomain_str,
	                          sizeof md5_signdomain_str);

	/* construct the query */
	snprintf(query, sizeof query, "%s.%s.%s.%s", md5_user_str,
	         md5_domain_str, md5_signdomain_str, qroot);

#ifdef USE_ARLIB
	lib = dkim->dkim_libhandle;
	ar = lib->dkiml_arlib;

	timeout.tv_sec = dkim->dkim_timeout;
	timeout.tv_usec = 0;

	q = ar_addquery(ar, query, C_IN, T_TXT, MAXCNAMEDEPTH, ansbuf,
	                sizeof ansbuf, &error,
	                dkim->dkim_timeout == 0 ? NULL : &timeout);
	if (q == NULL)
	{
		dkim_error(dkim, "ar_addquery() for `%s' failed", query);
		return -2;
	}

	if (lib->dkiml_dns_callback == NULL)
	{
		status = ar_waitreply(ar, q, &anslen, NULL);
	}
	else
	{
		for (;;)
		{
			timeout.tv_sec = lib->dkiml_callback_int;
			timeout.tv_usec = 0;

			status = ar_waitreply(ar, q, &anslen, &timeout);

			if (status != AR_STAT_NOREPLY)
				break;

			lib->dkiml_dns_callback(dkim->dkim_user_context);
		}
	}

	(void) ar_cancelquery(ar, q);
#else /* USE_ARLIB */
	status = res_query(query, C_IN, T_TXT, ansbuf, sizeof ansbuf);
#endif /* USE_ARLIB */

#if USE_ARLIB
	if (status == AR_STAT_ERROR || status == AR_STAT_EXPIRED)
	{
		dkim_error(dkim, "ar_waitreply(): `%s' %s", query,
		           status == AR_STAT_ERROR ? "error"
		                                   : "expired");
		return -1;
	}
#else /* USE_ARLIB */
	/*
	**  A -1 return from res_query could mean a bunch of things,
	**  not just NXDOMAIN.  You can use h_errno to determine what
	**  -1 means.  This is poorly documented.
	*/

	if (status == -1)
	{
		switch (h_errno)
		{
		  case HOST_NOT_FOUND:
		  case NO_DATA:
			return 0;

		  case TRY_AGAIN:
		  case NO_RECOVERY:
		  default:
			dkim_error(dkim, "res_query(): `%s' %s",
			           query, hstrerror(h_errno));
			return -1;
		}
	}

	anslen = status;
#endif /* USE_ARLIB */

	/* set up pointers */
	memcpy(&hdr, ansbuf, sizeof hdr);
	cp = (u_char *) &ansbuf + HFIXEDSZ;
	eom = (u_char *) &ansbuf + anslen;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		(void) dn_expand((unsigned char *) &ansbuf, eom, cp, qname,
		                 sizeof qname);

		if ((n = dn_skipname(cp, eom)) < 0)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			return -1;
		}
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			return -1;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_TXT || class != C_IN)
	{
		dkim_error(dkim, "`%s' unexpected reply type/class", query);
		return -1;
	}

	/* if NXDOMAIN, no data available */
	if (hdr.rcode == NXDOMAIN)
		return 0;

	/* if truncated, we can't do it */
	if (dkim_check_dns_reply(ansbuf, anslen, C_IN, T_TXT) == 1)
	{
		dkim_error(dkim, "`%s' reply truncated", query);
		return -1;
	}

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return 0;

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) &ansbuf, eom, cp,
		                   (RES_UNC_T) qname, sizeof qname)) < 0)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			return -1;
		}
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "`%s' reply corrupt", query);
			return -1;
		}

		GETSHORT(type, cp);
		GETSHORT(class, cp);

# ifdef QUERY_CACHE
		/* get the TTL */
		GETLONG(ttl, cp);
# else /* QUERY_CACHE */
		/* skip the TTL */
		cp += INT32SZ;
# endif /* QUERY_CACHE */

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			char chost[DKIM_MAXHOSTNAMELEN + 1];

			n = dn_expand((u_char *) &ansbuf, eom, cp,
			              chost, DKIM_MAXHOSTNAMELEN);
			cp += n;
			continue;
		}
		else if (type != T_TXT)
		{
			dkim_error(dkim, "`%s' reply was unexpected type %d",
			           query, type);
			return -1;
		}

		if (ancount > 0)
		{
			dkim_error(dkim, "multiple DNS replies for `%s'",
			           query);
			return -1;
		}

		/* found a record we can use; break */
		break;
	}

	/* if ancount went below 0, there were no good records */
	if (ancount < 0)
	{
		dkim_error(dkim, "`%s' reply was unresolved CNAME", query);
		return -1;
	}

	/* get payload length */
	if (cp + INT16SZ > eom)
	{
		dkim_error(dkim, "`%s' reply corrupt", query);
		return -1;
	}
	GETSHORT(n, cp);

	/*
	**  XXX -- maybe deal with a partial reply rather than require
	**  	   it all
	*/

	if (cp + n > eom)
	{
		dkim_error(dkim, "`%s' reply corrupt", query);
		return -1;
	}

	/* extract the payload */
	memset(buf, '\0', sizeof buf);
	p = buf;
	eob = buf + sizeof buf - 1;
	while (n > 0 && p < eob)
	{
		c = *cp++;
		n--;
		while (c > 0 && p < eob)
		{
			*p++ = *cp++;
			c--;
			n--;
		}
	}

	/* XXX -- should probably have caching for this stuff too */

	/* parse the result and return it */
	out = 0L;
	for (p = strtok_r(buf, ";", &ctx);
	     p != NULL;
	     p = strtok_r(NULL, ";", &ctx))
	{
		eq = strchr(p, '=');
		if (eq == NULL)
			continue;

		if (dkim_string_empty(eq + 1))
			continue;

		*eq = '\0';

		if (strcmp(p, "rep") != 0)
			continue;		/* XXX -- other values? */

		errno = 0;
		out = (int) strtol(eq + 1, &e, 10);
		if (*e != '\0' || errno == EINVAL)
		{
			dkim_error(dkim, "invalid reputation `%s'", eq + 1);
			return -1;
		}

		*rep = out;
		break;
	}

	return 1;
}
#endif /* _FFR_DKIM_REPUTATION */
