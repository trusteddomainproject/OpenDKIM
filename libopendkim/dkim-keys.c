/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dkim_keys_c_id[] = "@(#)$Id: dkim-keys.c,v 1.7 2009/10/06 17:45:55 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

/* libar includes */
#if USE_ARLIB
# include <ar.h>
#endif /* USE_ARLIB */

/* libopendkim includes */
#include "dkim-types.h"
#include "dkim-keys.h"
#include "dkim-cache.h"
#include "dkim-test.h"
#if USE_UNBOUND
# include "dkim-ub.h"
#endif /* USE_UNBOUND */
#include "util.h"
#include "dkim.h"
#include "dkim-strl.h"

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
**  DKIM_GET_KEY_DNS -- retrieve a DKIM key from DNS
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	buf -- buffer into which to write the result
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_get_key_dns(DKIM *dkim, DKIM_SIGINFO *sig, u_char *buf, size_t buflen)
{
#ifdef QUERY_CACHE
	bool cached = FALSE;
	uint32_t ttl = 0;
#endif /* QUERY_CACHE */
	int status;
	int qdcount;
	int ancount;
#if USE_ARLIB
	int error;
#endif /* USE_ARLIB */
	int c;
	int n = 0;
	int type = -1;
	int class = -1;
	size_t anslen;
#if USE_UNBOUND
	struct dkim_unbound_cb_data cb_data;
#endif /* USE_UNBOUND */
#if USE_ARLIB
	AR_LIB ar;
	AR_QUERY q;
#endif /* USE_ARLIB */
	DKIM_LIB *lib;
	unsigned char *p;
	unsigned char *cp;
	unsigned char *eom;
	unsigned char *eob;
	char qname[DKIM_MAXHOSTNAMELEN + 1];
	unsigned char ansbuf[MAXPACKET];
#if USE_ARLIB
	struct timeval timeout;
#endif /* USE_ARLIB */
	HEADER hdr;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(sig->sig_selector != NULL);
	assert(sig->sig_domain != NULL);
	assert(sig->sig_query == DKIM_QUERY_DNS);

	lib = dkim->dkim_libhandle;

	snprintf(qname, sizeof qname - 1, "%s.%s.%s", sig->sig_selector,
	         DKIM_DNSKEYNAME, sig->sig_domain);

#ifdef QUERY_CACHE
	/* see if we have this data already cached */
	if (dkim->dkim_libhandle->dkiml_cache != NULL)
	{
		int err = 0;
		size_t blen = buflen;

		dkim->dkim_cache_queries++;

		status = dkim_cache_query(dkim->dkim_libhandle->dkiml_cache,
		                          qname, 0, buf, &blen, &err);
		if (status == 0)
		{
			dkim->dkim_cache_hits++;
			return DKIM_STAT_OK;
		}
		/* XXX -- do something with errors here */
	}
#endif /* QUERY_CACHE */

	/* see if there's a simulated reply queued; if so, use it */
	anslen = dkim_test_dns_get(dkim, ansbuf, sizeof ansbuf);
	if (anslen == -1)
	{
#if USE_UNBOUND
		status = dkim_unbound_queue(dkim, qname, T_TXT,
		                            buf, buflen, &cb_data);

		if (status != 0)
		{
			dkim_error(dkim, "error queueing DNS request for `%s'",
			           qname);
			return DKIM_STAT_KEYFAIL;
		}

		status = dkim_unbound_wait(dkim, &cb_data);

		switch (status)
		{
		  case 1:
			sig->sig_dnssec_key = cb_data.ubd_result;
			break;

		  case 0:
			dkim_error(dkim, "timeout DNS query for `%s'", qname);
			return DKIM_STAT_KEYFAIL;

		  case -1:
			dkim_error(dkim, "error processing DNS query for `%s'",
			           qname);
			if (cb_data.ubd_stat != DKIM_STAT_OK)
				return cb_data.ubd_stat;
			else
				return DKIM_STAT_INTERNAL;
		}
	}
#else /* USE_UNBOUND */
# if USE_ARLIB
#  ifdef _FFR_DNS_UPGRADE
		for (c = 0; c < 2; c++)
		{
			switch (c)
			{
			  case 0:
				ar = dkim->dkim_libhandle->dkiml_arlib;
				break;

			  case 1:
				ar = dkim->dkim_libhandle->dkiml_arlibtcp;
				break;
			}

			timeout.tv_sec = dkim->dkim_timeout;
			timeout.tv_usec = 0;

			q = ar_addquery(ar, qname, C_IN, T_TXT, MAXCNAMEDEPTH,
			                ansbuf, sizeof ansbuf, &error,
			                dkim->dkim_timeout == 0 ? NULL
			                                        : &timeout);
			if (q == NULL)
			{
				dkim_error(dkim,
				           "ar_addquery() for `%s' failed",
				           qname);
				return DKIM_STAT_INTERNAL;
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

					status = ar_waitreply(ar, q, &anslen,
					                      &timeout);

					if (status != AR_STAT_NOREPLY)
						break;

					lib->dkiml_dns_callback(dkim->dkim_user_context);
				}
			}

			(void) ar_cancelquery(ar, q);

			/* see if the UDP reply was truncated */
			if (c == 0 && status == AR_STAT_SUCCESS)
			{
				memcpy(&hdr, ansbuf, sizeof hdr);
				if (dkim_check_dns_reply(ansbuf, anslen,
			                         C_IN, T_TXT) == 1)
					continue;
			}

			break;
		}
#  else /* _FFR_DNS_UPGRADE */
		ar = dkim->dkim_libhandle->dkiml_arlib;

		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		q = ar_addquery(ar, qname, C_IN, T_TXT, MAXCNAMEDEPTH, ansbuf,
		                sizeof ansbuf, &error,
		                dkim->dkim_timeout == 0 ? NULL : &timeout);
		if (q == NULL)
		{
			dkim_error(dkim, "ar_addquery() for `%s' failed",
			           qname);
			return DKIM_STAT_INTERNAL;
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

				status = ar_waitreply(ar, q, &anslen,
				                      &timeout);

				if (status != AR_STAT_NOREPLY)
					break;

				lib->dkiml_dns_callback(dkim->dkim_user_context);
			}
		}

		(void) ar_cancelquery(ar, q);
#  endif /* _FFR_DNS_UPGRADE */
# else /* USE_ARLIB */
		status = res_query(qname, C_IN, T_TXT, ansbuf, sizeof ansbuf);
# endif /* USE_ARLIB */

# if USE_ARLIB
		if (status == AR_STAT_ERROR || status == AR_STAT_EXPIRED)
		{
			dkim_error(dkim, "ar_waitreply(): `%s' %s", qname,
			           status == AR_STAT_ERROR ? "error"
			                                   : "expired");
			return DKIM_STAT_KEYFAIL;
		}
# else /* USE_ARLIB */
		/*
		**  A -1 return from res_query could mean a bunch of things,
		**  not just NXDOMAIN.  You can use h_errno to determine what
		**  -1 means.  This is poorly documented.
		*/

		if (status == -1)
		{
			dkim_error(dkim, "res_query(): `%s' %s",
			           qname, hstrerror(h_errno));

			switch (h_errno)
			{
			  case HOST_NOT_FOUND:
			  case NO_DATA:
				return DKIM_STAT_NOKEY;

			  case TRY_AGAIN:
			  case NO_RECOVERY:
			  default:
				return DKIM_STAT_KEYFAIL;
			}
		}

		anslen = status;
# endif /* USE_ARLIB */
	}

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
			dkim_error(dkim, "`%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
		}
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "`%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_TXT || class != C_IN)
	{
		dkim_error(dkim, "`%s' unexpected reply type/class", qname);
		return DKIM_STAT_KEYFAIL;
	}

	/* if NXDOMAIN, return DKIM_STAT_NOKEY */
	if (hdr.rcode == NXDOMAIN)
	{
		dkim_error(dkim, "`%s' record not found", qname);
		return DKIM_STAT_NOKEY;
	}

	/* if truncated, we can't do it */
	if (dkim_check_dns_reply(ansbuf, anslen, C_IN, T_TXT) == 1)
	{
		dkim_error(dkim, "`%s' reply truncated", qname);
		return DKIM_STAT_KEYFAIL;
	}

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return DKIM_STAT_NOKEY;

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) &ansbuf, eom, cp,
		                   (RES_UNC_T) qname, sizeof qname)) < 0)
		{
			dkim_error(dkim, "`%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
		}
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			dkim_error(dkim, "`%s' reply corrupt", qname);
			return DKIM_STAT_KEYFAIL;
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
			           qname, type);
			return DKIM_STAT_KEYFAIL;
		}

		if (ancount > 0)
		{
			dkim_error(dkim, "multiple DNS replies for `%s'",
			           qname);
			return DKIM_STAT_MULTIDNSREPLY;
		}

		/* found a record we can use; break */
		break;
	}

	/* if ancount went below 0, there were no good records */
	if (ancount < 0)
	{
		dkim_error(dkim, "`%s' reply was unresolved CNAME", qname);
		return DKIM_STAT_KEYFAIL;
	}

	/* get payload length */
	if (cp + INT16SZ > eom)
	{
		dkim_error(dkim, "`%s' reply corrupt", qname);
		return DKIM_STAT_KEYFAIL;
	}
	GETSHORT(n, cp);

	/*
	**  XXX -- maybe deal with a partial reply rather than require
	**  	   it all
	*/

	if (cp + n > eom)
	{
		dkim_error(dkim, "`%s' reply corrupt", qname);
		return DKIM_STAT_SYNTAX;
	}

	/* extract the payload */
	memset(buf, '\0', buflen);
	p = buf;
	eob = buf + buflen - 1;
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
#endif /* USE_UNBOUND */

#ifdef QUERY_CACHE
	if (!cached && buf[0] != '\0' &&
	    dkim->dkim_libhandle->dkiml_cache != NULL)
	{
		int err = 0;

		status = dkim_cache_insert(dkim->dkim_libhandle->dkiml_cache,
		                           qname, buf, ttl, &err);
		/* XXX -- do something with errors here */
	}
#endif /* QUERY_CACHE */

	return DKIM_STAT_OK;
}

/*
**  DKIM_GET_KEY_FILE -- retrieve a DKIM key from a text file (for testing)
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	buf -- buffer into which to write the result
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Notes:
**  	The file opened is defined by the library option DKIM_OPTS_QUERYINFO
**  	and must be set prior to use of this function.  Failing to do
**  	so will cause this function to return DKIM_STAT_KEYFAIL every time.
**  	The file should contain lines of the form:
** 
**  		<selector>._domainkey.<domain> <space> key-data
**
**  	Case matching on the left is case-sensitive, but libopendkim already
**  	wraps the domain name to lowercase.
*/

DKIM_STAT
dkim_get_key_file(DKIM *dkim, DKIM_SIGINFO *sig, u_char *buf, size_t buflen)
{
	FILE *f;
	u_char *p;
	u_char *p2;
	char *path;
	char name[BUFRSZ + 1];

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(sig->sig_selector != NULL);
	assert(sig->sig_domain != NULL);
	assert(sig->sig_query == DKIM_QUERY_FILE);

	path = dkim->dkim_libhandle->dkiml_queryinfo;
	if (path[0] == '\0')
	{
		dkim_error(dkim, "query file not defined");
		return DKIM_STAT_KEYFAIL;
	}

	f = fopen(path, "r");
	if (f == NULL)
	{
		dkim_error(dkim, "%s: fopen(): %s", path, strerror(errno));
		return DKIM_STAT_KEYFAIL;
	}

	snprintf(name, sizeof name, "%s.%s.%s", sig->sig_selector,
	         DKIM_DNSKEYNAME, sig->sig_domain);

	memset(buf, '\0', buflen);
	while (fgets(buf, buflen, f) != NULL)
	{
		p2 = NULL;

		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n')
			{
				*p = '\0';
				break;
			}
			else if (isascii(*p) && isspace(*p))
			{
				*p = '\0';
				p2 = p + 1;
			}
			else if (p2 != NULL)
			{
				break;
			}
		}

		if (strcasecmp(name, buf) == 0 && p2 != NULL)
		{
			strlcpy(buf, p2, buflen);
			fclose(f);
			return DKIM_STAT_OK;
		}
	}

	fclose(f);

	return DKIM_STAT_NOKEY;
}
