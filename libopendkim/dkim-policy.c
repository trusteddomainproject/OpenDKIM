/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dkim_policy_c_id[] = "@(#)$Id: dkim-policy.c,v 1.2 2009/07/20 18:52:39 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

/* libar includes */
#if USE_ARLIB
# include <ar.h>
#endif /* USE_ARLIB */

/* libdkim includes */
#include "dkim.h"
#include "dkim-types.h"
#include "dkim-policy.h"
#ifdef QUERY_CACHE
# include "dkim-cache.h"
#endif /* QUERY_CACHE */
#ifdef USE_UNBOUND
# include "dkim-ub.h"
#endif /* USE_UNBOUND */
#include "dkim-test.h"
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

			sm_strlcpy(buf, p, buflen);

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
#if USE_ARLIB
	int c;
	size_t anslen_a;
	size_t anslen_aaaa;
	size_t anslen_mx;
#endif /* USE_ARLIB */
	int status;
#if USE_UNBOUND
	int c;
	int qtype;
	unsigned char *outbuf;
	size_t outsize;
	struct dkim_unbound_cb_data cb_data;
#endif /* USE_UNBOUND */
	DKIM_LIB *lib;
	HEADER hdr;
#if USE_ARLIB
	AR_LIB ar;
	AR_QUERY q_a;
	AR_QUERY q_aaaa;
	AR_QUERY q_mx;
	int arerror_a;
	int arerror_aaaa;
	int arerror_mx;
	struct timeval timeout;
#endif /* USE_ARLIB */
	unsigned char ansbuf_a[MAXPACKET];
	unsigned char ansbuf_aaaa[MAXPACKET];
	unsigned char ansbuf_mx[MAXPACKET];

	assert(dkim != NULL);
	assert(query != NULL);
	assert(qstatus != NULL);

	lib = dkim->dkim_libhandle;

#if USE_UNBOUND
	for (c = 0; c < 3; c++)
	{
		if (c == 0)
		{
			qtype = T_A;
			outbuf = ansbuf_a;
			outsize = sizeof ansbuf_a;
		}
# ifdef T_AAAA
		else if (c == 1)
		{
			qtype = T_AAAA;			/* AAAA */
			outbuf = ansbuf_aaaa;
			outsize = sizeof ansbuf_aaaa;
		}
		else if (c == 2)
		{
			qtype = T_MX;			/* MX */
			outbuf = ansbuf_mx;
			outsize = sizeof ansbuf_mx;
		}
# else /* T_AAAA */
		else if (c == 1)
		{
			qtype = T_MX;			/* MX */
			outbuf = ansbuf_mx;
			outsize = sizeof ansbuf_mx;
		}
		else if (c == 2)
		{
			break;
		}
# endif /* T_AAAA */

		/* query */
		status = dkim_unbound_queue(dkim, query, qtype, 
		                            outbuf, outsize, &cb_data);

		if (status != 0)
		{
			dkim_error(dkim, "error queueing DNS request for `%s'",
			           query);
			return -1;
		}

		status = dkim_unbound_wait(dkim, &cb_data);

		switch (status)
		{
		  case 1:
			break;

		  case 0:
			dkim_error(dkim, "timeout DNS query for `%s'", query);
			return -1;

		  case -1:
			dkim_error(dkim,
			           "error processing DNS query for `%s'",
			           query);
			return -1;
		}

		*qstatus = cb_data.ubd_rcode;

		if (cb_data.ubd_rcode == NOERROR)
			return 1;
	}

	return 0;
#endif /* USE_UNBOUND */

#if USE_ARLIB
# ifdef _FFR_DNS_UPGRADE
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

		q_a = ar_addquery(ar, query, C_IN, T_A, MAXCNAMEDEPTH,
		                  ansbuf_a, sizeof ansbuf_a, &arerror_a,
		                  dkim->dkim_timeout == 0 ? NULL
		                                          : &timeout);
		if (q_a == NULL)
		{
			dkim_error(dkim, "ar_addquery() for `%s' failed",
			           query);
			return -1;
		}

		q_aaaa = ar_addquery(ar, query, C_IN, T_AAAA, MAXCNAMEDEPTH,
		                     ansbuf_aaaa, sizeof ansbuf_aaaa,
		                     &arerror_aaaa,
		                     dkim->dkim_timeout == 0 ? NULL
		                                             : &timeout);
		if (q_aaaa == NULL)
		{
			dkim_error(dkim, "ar_addquery() for `%s' failed",
			           query);
			return -1;
		}

		q_mx = ar_addquery(ar, query, C_IN, T_MX, MAXCNAMEDEPTH,
		                   ansbuf_mx, sizeof ansbuf_mx,
		                   &arerror_mx,
		                   dkim->dkim_timeout == 0 ? NULL
		                                           : &timeout);
		if (q_mx == NULL)
		{
			dkim_error(dkim, "ar_addquery() for `%s' failed",
			           query);
			return -1;
		}

		if (lib->dkiml_dns_callback == NULL)
		{
			status = ar_waitreply(ar, q_a, &anslen_a, NULL);
			status = ar_waitreply(ar, q_aaaa, &anslen_aaaa, NULL);
			status = ar_waitreply(ar, q_mx, &anslen_mx, NULL);
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
					status = ar_waitreply(ar, q_a,
					                      &anslen_a,
					                      &timeout);
					break;

				  case 1:
					status = ar_waitreply(ar, q_aaaa,
					                      &anslen_aaaa,
					                      &timeout);
					break;

				  case 2:
					status = ar_waitreply(ar, q_mx,
					                      &anslen_mx,
					                      &timeout);
					break;
				}

				if (status != AR_STAT_NOREPLY)
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

		(void) ar_cancelquery(ar, q_a);
		(void) ar_cancelquery(ar, q_aaaa);
		(void) ar_cancelquery(ar, q_mx);

		/* see if any of the UDP replies was truncated */
		if (c == 0 && status == AR_STAT_SUCCESS)
		{
			if (dkim_check_dns_reply(ansbuf_a, anslen_a,
			                         C_IN, T_TXT) == 1)
				continue;

			if (dkim_check_dns_reply(ansbuf_aaaa, anslen_aaaa,
			                         C_IN, T_TXT) == 1)
				continue;

			if (dkim_check_dns_reply(ansbuf_mx, anslen_mx,
			                         C_IN, T_TXT) == 1)
				continue;
		}

		break;
	}
# else /* _FFR_DNS_UPGRADE */
	ar = dkim->dkim_libhandle->dkiml_arlib;

	timeout.tv_sec = dkim->dkim_timeout;
	timeout.tv_usec = 0;

	q_a = ar_addquery(ar, query, C_IN, T_A, MAXCNAMEDEPTH, ansbuf_a,
	                  sizeof ansbuf_a, &arerror_a,
	                  dkim->dkim_timeout == 0 ? NULL : &timeout);
	if (q_a == NULL)
	{
		dkim_error(dkim, "ar_addquery() failed for `%s'",
		           query);
		return -1;
	}

	q_aaaa = ar_addquery(ar, query, C_IN, T_AAAA, MAXCNAMEDEPTH,
	                     ansbuf_aaaa, sizeof ansbuf_aaaa, &arerror_aaaa,
	                     dkim->dkim_timeout == 0 ? NULL : &timeout);
	if (q_aaaa == NULL)
	{
		dkim_error(dkim, "ar_addquery() failed for `%s'",
		           query);
		return -1;
	}

	q_mx = ar_addquery(ar, query, C_IN, T_MX, MAXCNAMEDEPTH,
	                   ansbuf_mx, sizeof ansbuf_mx, &arerror_mx,
	                   dkim->dkim_timeout == 0 ? NULL : &timeout);
	if (q_mx == NULL)
	{
		dkim_error(dkim, "ar_addquery() failed for `%s'",
		           query);
		return -1;
	}

	if (lib->dkiml_dns_callback == NULL)
	{
		status = ar_waitreply(ar, q_a, &anslen_a, NULL);
		status = ar_waitreply(ar, q_aaaa, &anslen_aaaa, NULL);
		status = ar_waitreply(ar, q_mx, &anslen_mx, NULL);
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
				status = ar_waitreply(ar, q_a,
				                      &anslen_a,
				                      &timeout);
				break;

			  case 1:
				status = ar_waitreply(ar, q_aaaa,
				                      &anslen_aaaa,
				                      &timeout);
				break;

			  case 2:
				status = ar_waitreply(ar, q_mx,
				                      &anslen_mx,
				                      &timeout);
				break;
			}

			if (status != AR_STAT_NOREPLY)
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

	(void) ar_cancelquery(ar, q_a);
	(void) ar_cancelquery(ar, q_aaaa);
	(void) ar_cancelquery(ar, q_mx);
# endif /* _FFR_DNS_UPGRADE */
#else /* USE_ARLIB */
	status = res_query(query, C_IN, T_A, ansbuf_a, sizeof ansbuf_a);
	status = res_query(query, C_IN, T_AAAA, ansbuf_aaaa,
	                   sizeof ansbuf_aaaa);
	status = res_query(query, C_IN, T_MX, ansbuf_mx, sizeof ansbuf_mx);
#endif /* USE_ARLIB */

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
	int ttl;
#endif /* QUERY_CACHE */
#if USE_UNBOUND
	struct dkim_unbound_cb_data cb_data;
	struct dkim_unbound_cb_data *cb_data_ptr = &cb_data;
#endif /* USE_UNBOUND */
	size_t anslen;
#if USE_ARLIB
	AR_LIB ar;
	AR_QUERY q;
	int arerror;
#endif /* USE_ARLIB */
	DKIM_LIB *lib;
	unsigned char *p;
	unsigned char *cp;
	unsigned char *eom;
	unsigned char ansbuf[MAXPACKET];
	unsigned char namebuf[DKIM_MAXHOSTNAMELEN + 1];
	unsigned char outbuf[BUFRSZ + 1];
#if USE_ARLIB
	struct timeval timeout;
#endif /* USE_ARLIB */
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
#ifdef USE_UNBOUND
	status = dkim_unbound_queue(dkim, query, T_TXT, buf, buflen, &cb_data);

	if (status != 0)
	{
		dkim_error(dkim, "error queueing DNS request for `%s'",
		           query);
		return -1;
	}

	status = dkim_unbound_wait(dkim, &cb_data);

	switch (status)
	{
	  case 1:
		dkim->dkim_dnssec_policy = cb_data_ptr->ubd_result;
		break;

	  case 0:
		dkim_error(dkim, "timeout DNS query for `%s'", query);
		return -1;

	  case -1:
		dkim_error(dkim, "error processing DNS query for `%s'", query);
		return -1;
	}

	if (cb_data_ptr->ubd_stat != DKIM_STAT_OK)
	{
		if (cb_data_ptr->ubd_stat == DKIM_STAT_NOKEY)
		{
			return 0;
		}
		else
		{
			dkim_error(dkim, "error processing DNS policy query");
			return -1;
		}
	}
}

#else /* USE_UNBOUND */
#if USE_ARLIB
# ifdef _FFR_DNS_UPGRADE
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

			q = ar_addquery(ar, query, C_IN, T_TXT, MAXCNAMEDEPTH,
			                ansbuf, sizeof ansbuf, &arerror,
			                dkim->dkim_timeout == 0 ? NULL
			                                        : &timeout);
			if (q == NULL)
			{
				dkim_error(dkim,
				           "ar_addquery() for `%s' failed",
				           query);
				return -1;
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
# else /* _FFR_DNS_UPGRADE */
		ar = dkim->dkim_libhandle->dkiml_arlib;

		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		q = ar_addquery(ar, query, C_IN, T_TXT, MAXCNAMEDEPTH, ansbuf,
		                sizeof ansbuf, &arerror,
		                dkim->dkim_timeout == 0 ? NULL : &timeout);
		if (q == NULL)
		{
			dkim_error(dkim, "ar_addquery() failed for `%s'",
			           query);
			return -1;
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
# endif /* _FFR_DNS_UPGRADE */
#else /* USE_ARLIB */

		status = res_query(query, C_IN, T_TXT, ansbuf, sizeof ansbuf);

#endif /* USE_ARLIB */

#if USE_ARLIB
		if (status == AR_STAT_ERROR || status == AR_STAT_EXPIRED)
		{
			dkim_error(dkim, "ar_waitreply(): `%s' query %s",
			           query,
			           status == AR_STAT_ERROR ? "error"
			                                   : "expired");

			if (status == AR_STAT_EXPIRED)
			{
				*qstatus = SERVFAIL;
				return 0;
			}
			else
			{
				return -1;
			}
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
				*qstatus = NXDOMAIN;
				return 0;

			  case NO_DATA:
				*qstatus = NOERROR;
				return 0;

			  case TRY_AGAIN:
			  case NO_RECOVERY:
			  default:
				dkim_error(dkim, "res_query(): `%s' %s",
				           query, hstrerror(h_errno));
				*qstatus = SERVFAIL;
				return 0;
			}
		}

		anslen = status;
#endif /* USE_ARLIB */
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

	sm_strlcpy(buf, outbuf, buflen);
#endif /* USE_UNBOUND */

	return 1;
}
