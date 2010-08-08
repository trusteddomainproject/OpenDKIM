/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dkim_policy_c_id[] = "@(#)$Id: dkim-policy.c,v 1.11.14.1 2010/08/08 07:19:10 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdbool.h>
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include "build-config.h"

/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-types.h"
#include "dkim-policy.h"
#ifdef QUERY_CACHE
# include "dkim-cache.h"
#endif /* QUERY_CACHE */
#include "dkim-test.h"
#include "util.h"
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

#ifndef T_AAAA
# define T_AAAA	28
#endif /* ! T_AAAA */

/*
**  DKIM_GET_POLICY_FILE -- acquire a domain's policy record using a local file
**
**  Parameters:
**  	dkim -- DKIM handle
**  	query -- query to execute
**  	buf -- buffer into which to write policy
**  	buflen -- number of bytes available at "buf"
**  	qstatus -- query result code (DNS-style)
**
**  Return value:
**  	1 -- query completed, answer returned in "buf"
**  	0 -- query completed, no answer available
**  	-1 -- failure
*/

int
dkim_get_policy_file(DKIM *dkim, unsigned char *query, unsigned char *buf,
                     size_t buflen, int *qstatus)
{
	_Bool found;
	int n;
	char *path;
	unsigned char *p;
	FILE *f;
	unsigned char inbuf[BUFRSZ + 1];

	assert(dkim != NULL);
	assert(query != NULL);
	assert(buf != NULL);
	assert(qstatus != NULL);

	path = dkim->dkim_libhandle->dkiml_queryinfo;

	f = fopen(path, "r");
	if (f == NULL)
	{
		dkim_error(dkim, "%s: fopen(): %s", path,
		           strerror(errno));
		return -1;
	}

	n = strlen(query);

	memset(inbuf, '\0', sizeof inbuf);

	found = FALSE;
	while (!found && fgets(inbuf, sizeof inbuf - 1, f) != NULL)
	{
		for (p = inbuf; *p != '\0'; p++)
		{
			if (*p == '\n' || *p == '#')
			{
				*p = '\0';
				break;
			}
		}

		/* is this a match? */
		if (strncasecmp(inbuf, query, n) == 0 &&
		    isascii(inbuf[n]) && isspace(inbuf[n]))
		{
			found = TRUE;

			/* move past spaces */
			for (p = &inbuf[n] + 1;
			     isascii(*p) && isspace(*p);
			     p++)
				continue;

			strlcpy(buf, p, buflen);

			*qstatus = NOERROR;

			fclose(f);

			return 1;
		}
	}

	if (ferror(f))
	{
		dkim_error(dkim, "%s: fgets(): %s", path, strerror(errno));
		fclose(f);
		return -1;
	}

	fclose(f);

	*qstatus = NXDOMAIN;

	return 0;
}

/*
**  DKIM_GET_POLICY_DNS_EXCHECK -- existence check for a name
**
**  Parameters:
**  	dkim -- DKIM handle
**  	query -- query to execute
**  	qstatus -- query result code (DNS-style)
**
**  Return value:
**  	1 -- domain exists
**  	0 -- domain does not exist
**  	-1 failure
*/

int
dkim_get_policy_dns_excheck(DKIM *dkim, unsigned char *query, int *qstatus)
{
	int c;
	size_t anslen_a;
	size_t anslen_aaaa;
	size_t anslen_mx;
	int status;
	DKIM_LIB *lib;
	HEADER hdr;
	void *q_a;
	void *q_aaaa;
	void *q_mx;
	int error_a;
	int error_aaaa;
	int error_mx;
	struct timeval timeout;
	unsigned char ansbuf_a[MAXPACKET];
	unsigned char ansbuf_aaaa[MAXPACKET];
	unsigned char ansbuf_mx[MAXPACKET];

	assert(dkim != NULL);
	assert(query != NULL);
	assert(qstatus != NULL);

	lib = dkim->dkim_libhandle;

	timeout.tv_sec = dkim->dkim_timeout;
	timeout.tv_usec = 0;

	anslen_a = sizeof ansbuf_a;
	status = lib->dkiml_dns_start(lib->dkiml_dns_service, T_A, query,
	                              ansbuf_a, anslen_a, &q_a);

	if (status != 0 || q_a == NULL)
	{
		dkim_error(dkim, "A query failed for `%s'", query);
		return -1;
	}

	anslen_aaaa = sizeof ansbuf_aaaa;
	status = lib->dkiml_dns_start(lib->dkiml_dns_service, T_AAAA, query,
	                              ansbuf_aaaa, anslen_aaaa, &q_aaaa);
	if (status != 0 || q_aaaa == NULL)
	{
		(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q_a);
		dkim_error(dkim, "AAAA query failed for `%s'", query);
		return -1;
	}

	anslen_mx = sizeof ansbuf_mx;
	status = lib->dkiml_dns_start(lib->dkiml_dns_service, T_MX, query,
	                              ansbuf_mx, anslen_mx, &q_mx);
	if (status != 0 || q_mx == NULL)
	{
		(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q_a);
		(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q_aaaa);
		dkim_error(dkim, "MX query failed for `%s'", query);
		return -1;
	}

	if (lib->dkiml_dns_callback == NULL)
	{
		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
		                                  q_a,
	                                          dkim->dkim_timeout == 0 ? NULL
	                                                                  : &timeout,
		                                  &anslen_a, NULL, NULL);

		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
		                                  q_aaaa,
	                                          dkim->dkim_timeout == 0 ? NULL
	                                                                  : &timeout,
		                                  &anslen_aaaa, NULL, NULL);

		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
		                                  q_mx,
	                                          dkim->dkim_timeout == 0 ? NULL
	                                                                  : &timeout,
		                                  &anslen_mx, NULL, NULL);
	}
	else
	{
		int which = 0;
 
		while (which <= 2)
		{
			timeout.tv_sec = lib->dkiml_callback_int;
			timeout.tv_usec = 0;

			switch (which)
			{
			  case 0:
				status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
				                                  q_a,
			                                          dkim->dkim_timeout == 0 ? NULL
			                                                                  : &timeout,
				                                  &anslen_a,
				                                  NULL, NULL);

				break;

			  case 1:
				status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
				                                  q_aaaa,
			                                          dkim->dkim_timeout == 0 ? NULL
			                                                                  : &timeout,
				                                  &anslen_aaaa,
				                                  NULL, NULL);

				break;

			  case 2:
				status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
				                                  q_mx,
			                                          dkim->dkim_timeout == 0 ? NULL
			                                                                  : &timeout,
				                                  &anslen_mx,
				                                  NULL, NULL);

				break;
			}

			if (status != DKIM_DNS_NOREPLY)
			{
				if (which == 2)
				{
					break;
				}
				else
				{
					which++;
					continue;
				}
			}

			lib->dkiml_dns_callback(dkim->dkim_user_context);
		}
	}

	(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q_a);
	(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q_aaaa);
	(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q_mx);

	/* check each for NXDOMAIN or some other issue */
	memcpy(&hdr, ansbuf_a, sizeof hdr);
	*qstatus = hdr.rcode;
	if (hdr.rcode == NOERROR)
		return 1;

	memcpy(&hdr, ansbuf_aaaa, sizeof hdr);
	*qstatus = hdr.rcode;
	if (hdr.rcode == NOERROR)
		return 1;

	memcpy(&hdr, ansbuf_mx, sizeof hdr);
	*qstatus = hdr.rcode;
	if (hdr.rcode == NOERROR)
		return 1;

	/* looks good */
	return 0;
}

/*
**  DKIM_GET_POLICY_DNS -- acquire a domain's policy record using DNS queries
**
**  Parameters:
**  	dkim -- DKIM handle
**  	query -- query to execute
**  	excheck -- existence check?
**  	buf -- buffer into which to write policy
**  	buflen -- number of bytes available at "buf"
**  	qstatus -- query result code (DNS-style)
**
**  Return value:
**  	1 -- policy retrieved, stored in buffer
**  	0 -- no policy found
**  	-1 -- failure
*/

int
dkim_get_policy_dns(DKIM *dkim, unsigned char *query, _Bool excheck,
                    unsigned char *buf, size_t buflen, int *qstatus)
{
	int qdcount;
	int ancount;
	int status;
	int n;
	int c;
	int type = -1;
	int class = -1;
#ifdef QUERY_CACHE
	uint32_t ttl;
#endif /* QUERY_CACHE */
	size_t anslen;
	void *q;
	int arerror;
	DKIM_LIB *lib;
	unsigned char *p;
	unsigned char *cp;
	unsigned char *eom;
	unsigned char ansbuf[MAXPACKET];
	unsigned char namebuf[DKIM_MAXHOSTNAMELEN + 1];
	unsigned char outbuf[BUFRSZ + 1];
	struct timeval timeout;
	HEADER hdr;

	assert(dkim != NULL);
	assert(query != NULL);
	assert(buf != NULL);
	assert(qstatus != NULL);

	lib = dkim->dkim_libhandle;

#ifdef QUERY_CACHE
	if (lib->dkiml_cache != NULL)
	{
		int err = 0;
		size_t blen = buflen;

		dkim->dkim_cache_queries++;

		status = dkim_cache_query(lib->dkiml_cache, query, 0,
		                          buf, &blen, &err);

		if (status == 0)
		{
			dkim->dkim_cache_hits++;
			return (status == DKIM_STAT_OK ? 0 : -1);
		}
		/* XXX -- do something with errors here */
	}
#endif /* QUERY_CACHE */

	/* see if there's a simulated reply queued; if so, use it */
	anslen = dkim_test_dns_get(dkim, ansbuf, sizeof ansbuf);
	if (anslen == -1)
	{
		if (excheck)
		{
			return dkim_get_policy_dns_excheck(dkim, query,
			                                   qstatus);
		}

		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		anslen = sizeof ansbuf;

		status = lib->dkiml_dns_start(lib->dkiml_dns_service,
		                              T_TXT, query,
		                              ansbuf, anslen, &q);
		if (status != 0 || q == NULL)
		{
			dkim_error(dkim, "query failed for `%s'", query);
			return -1;
		}

		if (lib->dkiml_dns_callback == NULL)
		{
			status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
			                                  q, NULL, &anslen,
			                                  NULL,
			                                  &dkim->dkim_dnssec_policy);
		}
		else
		{
			for (;;)
			{
				timeout.tv_sec = lib->dkiml_callback_int;
				timeout.tv_usec = 0;

				status = lib->dkiml_dns_waitreply(lib->dkiml_dns_service,
				                                  q,
				                                  &timeout,
				                                  &anslen,
				                                  NULL,
				                                  &dkim->dkim_dnssec_policy);

				if (status != DKIM_DNS_NOREPLY)
					break;

				lib->dkiml_dns_callback(dkim->dkim_user_context);
			}
		}

		(void) lib->dkiml_dns_cancel(lib->dkiml_dns_service, q);

		if (status == DKIM_DNS_ERROR || status == DKIM_DNS_EXPIRED)
		{
			dkim_error(dkim, "`%s' query %s", query,
			           status == DKIM_DNS_ERROR ? "error"
			                                    : "expired");

			if (status == DKIM_DNS_EXPIRED)
			{
				*qstatus = SERVFAIL;
				return 0;
			}
			else
			{
				return -1;
			}
		}
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
		(void) dn_expand((unsigned char *) &ansbuf, eom, cp,
		                 namebuf, sizeof namebuf);

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
		dkim_error(dkim, "`%s' unexpected reply class/type", query);
		return -1;
	}

	/* if truncated, we can't do it */
	if (dkim_check_dns_reply(ansbuf, anslen, C_IN, T_TXT) == 1)
	{
		dkim_error(dkim, "reply for `%s' truncated", query);
		return -1;
	}

	/* if we got something other than NOERROR, just return it */
	*qstatus = hdr.rcode;
	if (hdr.rcode != NOERROR)
		return 0;

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return 0;

	/* walk through the answers looking for the right record */
	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) &ansbuf, eom, cp,
		                   (RES_UNC_T) namebuf, sizeof namebuf)) < 0)
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

		/* handle a CNAME (skip it; assume it was resolved) */
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
			/* reject anything not valid (e.g. wildcards) */
			dkim_error(dkim, "`%s' unexpected reply class/type",
			           query);
			return -1;
		}

		if (ancount > 0)
		{
			dkim_error(dkim, "multiple DNS replies for `%s'",
			           query);
			return DKIM_STAT_MULTIDNSREPLY;
		}

		/* process it */
		break;
	}

	if (ancount < 0)
	{
		dkim_error(dkim, "`%s' reply was unresolved CNAME", query);
		return -1;
	}

#ifdef QUERY_CACHE
	GETLONG(ttl, cp);
#else /* QUERY_CACHE */
	/* skip the TTL */
	cp += INT32SZ;
#endif /* QUERY_CACHE */

	/* get payload length */
	if (cp + INT16SZ > eom)
	{
		dkim_error(dkim, "`%s' reply corrupt", query);
		return -1;
	}
	GETSHORT(n, cp);

	/* XXX -- maybe deal with a partial reply rather than require it all */
	if (cp + n > eom || n > BUFRSZ)
	{
		dkim_error(dkim, "`%s' reply corrupt", query);
		return -1;
	}

	/* extract the payload */
	memset(outbuf, '\0', sizeof outbuf);
	p = outbuf;
	eom = outbuf + sizeof outbuf - 1;
	while (n > 0 && p < eom)
	{
		c = *cp++;
		n--;
		while (c > 0 && p < eom)
		{
			*p++ = *cp++;
			c--;
			n--;
		}
	}

#ifdef QUERY_CACHE
	if (dkim->dkim_libhandle->dkiml_cache != NULL)
	{
		int err = 0;

		status = dkim_cache_insert(dkim->dkim_libhandle->dkiml_cache,
		                           query, outbuf, ttl, &err);
		/* XXX -- do something with errors here */
	}
#endif /* QUERY_CACHE */

	strlcpy(buf, outbuf, buflen);

	return 1;
}
