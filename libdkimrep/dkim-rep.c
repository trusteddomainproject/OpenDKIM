/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
*/

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
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>

#ifdef USE_GNUTLS
/* GnuTLS includes */
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
# ifndef MD5_DIGEST_LENGTH
#  define MD5_DIGEST_LENGTH 16
# endif /* ! MD5_DIGEST_LENGTH */
#else /* USE_GNUTLS */
/* openssl includes */
# include <openssl/md5.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "dkim-rep.h"

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

/* other local definitions */
#define	BUFRSZ			1024
#define	DKIM_REP_DEFTIMEOUT	5
#define	DKIM_REP_MAXERRORSTRING	256
#define	DKIM_REP_MAXHOSTNAMELEN	256

#ifndef FALSE
# define FALSE			0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE			1
#endif /* ! TRUE */

/* struct dkim_rep_query -- an open DKIM_REP query */
struct dkim_rep_query
{
	void *			drq_qh;
	size_t			drq_anslen;
	u_char			drq_buf[HFIXEDSZ + MAXPACKET];
};

/* struct dkim_rep_handle -- a DKIM_REP library context */
struct dkim_rep_handle
{
	u_int		dkim_rep_timeout;
	u_int		dkim_rep_cbint;
	void *		dkim_rep_cbctx;
	void *		dkim_rep_closure;
	void *		(*dkim_rep_malloc) (void *closure, size_t nbytes);
	void		(*dkim_rep_free) (void *closure, void *p);
	void		(*dkim_rep_dns_callback) (const void *context);
	void *		dkim_rep_dns_service;
	int		(*dkim_rep_dns_start) (void *srv, int type,
			                  unsigned char *query,
			                  unsigned char *buf,
			                  size_t buflen,
			                  void **qh);
	int		(*dkim_rep_dns_cancel) (void *srv, void *qh);
	int		(*dkim_rep_dns_init) (void **srv);
	int		(*dkim_rep_dns_close) (void *srv);
	int		(*dkim_rep_dns_config) (void *srv, const char *config);
	int		(*dkim_rep_dns_setns) (void *srv, const char *nslist);
	int		(*dkim_rep_dns_trustanchor) (void *srv,
			                             const char *trust);
	int		(*dkim_rep_dns_waitreply) (void *srv,
			                      void *qh,
			                      struct timeval *to,
			                      size_t *bytes,
			                      int *error,
			                      int *dnssec);
	u_char		dkim_rep_qroot[DKIM_REP_MAXHOSTNAMELEN + 1];
	u_char		dkim_rep_error[DKIM_REP_MAXERRORSTRING + 1];
};

/*
**  Standard UNIX resolver stub functions
*/

struct dkim_rep_res_qh
{
	int		rq_error;
	size_t		rq_buflen;
};

/*
**  DKIM_REP_RES_CANCEL -- cancel a pending resolver query
**
**  Parameters:
**  	srv -- query service handle (ignored)
**  	qh -- query handle (ignored)
**
**  Return value:
**  	0 on success, !0 on error
**
**  Notes:
**  	The standard UNIX resolver is synchronous, so in theory this can
**  	never get called.  We have not yet got any use cases for one thread
**  	canceling another thread's pending queries, so for now just return 0.
*/

static int
dkim_rep_res_cancel(void *srv, void *qh)
{
	if (qh != NULL)
		free(qh);

	return 0;
}

/*
**  DKIM_REP_RES_QUERY -- initiate a DNS query
**
**  Parameters:
**  	srv -- service handle (ignored)
**  	type -- RR type to query
**  	query -- the question to ask
**  	buf -- where to write the answer
**  	buflen -- bytes at "buf"
** 	qh -- query handle, used with rbl_res_waitreply
**
**  Return value:
**  	An DKIM_REP_DNS_* constant.
**
**  Notes:
**  	This is a stub for the stock UNIX resolver (res_) functions, which
**  	are synchronous so no handle needs to be created, so "qh" is set to
**  	"buf".  "buf" is actually populated before this returns (unless
**  	there's an error).
*/

static int
dkim_rep_res_query(void *srv, int type, unsigned char *query,
                   unsigned char *buf, size_t buflen, void **qh)
{
	int n;
	int ret;
	struct dkim_rep_res_qh *rq;
	unsigned char qbuf[HFIXEDSZ + MAXPACKET];
#ifdef HAVE_RES_NINIT
	struct __res_state statp;
#endif /* HAVE_RES_NINIT */

#ifdef HAVE_RES_NINIT
	memset(&statp, '\0', sizeof statp);
	res_ninit(&statp);
#endif /* HAVE_RES_NINIT */

#ifdef HAVE_RES_NINIT
	n = res_nmkquery(&statp, QUERY, (char *) query, C_IN, type, NULL, 0,
	                 NULL, qbuf, sizeof qbuf);
#else /* HAVE_RES_NINIT */
	n = res_mkquery(QUERY, (char *) query, C_IN, type, NULL, 0, NULL, qbuf,
	                sizeof qbuf);
#endif /* HAVE_RES_NINIT */
	if (n == (size_t) -1)
	{
#ifdef HAVE_RES_NINIT
		res_nclose(&statp);
#endif /* HAVE_RES_NINIT */
		return DKIM_REP_DNS_ERROR;
	}

#ifdef HAVE_RES_NINIT
	ret = res_nsend(&statp, qbuf, n, buf, buflen);
#else /* HAVE_RES_NINIT */
	ret = res_send(qbuf, n, buf, buflen);
#endif /* HAVE_RES_NINIT */
	if (ret == -1)
	{
#ifdef HAVE_RES_NINIT
		res_nclose(&statp);
#endif /* HAVE_RES_NINIT */
		return DKIM_REP_DNS_ERROR;
	}

#ifdef HAVE_RES_NINIT
	res_nclose(&statp);
#endif /* HAVE_RES_NINIT */

	rq = (struct dkim_rep_res_qh *) malloc(sizeof *rq);
	if (rq == NULL)
		return DKIM_REP_DNS_ERROR;

	if (ret == -1)
	{
		rq->rq_error = errno;
		rq->rq_buflen = 0;
	}
	else
	{
		rq->rq_error = 0;
		rq->rq_buflen = (size_t) ret;
	}

	*qh = (void *) rq;

	return DKIM_REP_DNS_SUCCESS;
}

/*
**  DKIM_REP_RES_WAITREPLY -- wait for a reply to a pending query
**
**  Parameters:
**  	srv -- service handle
**  	qh -- query handle
**  	to -- timeout
**  	bytes -- number of bytes in the reply (returned)
**  	error -- error code (returned)
**
**  Return value:
**  	A DKIM_REP_DNS_* code.
**
**  Notes:
**  	Since the stock UNIX resolver is synchronous, the reply was completed
** 	before rbl_res_query() returned, and thus this is almost a no-op.
*/

int
dkim_rep_res_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                       int *error, int *dnssec)
{
	struct dkim_rep_res_qh *rq;

	assert(qh != NULL);

	rq = qh;

	if (bytes != NULL)
		*bytes = rq->rq_buflen;
	if (error != NULL)
		*error = rq->rq_error;

	return DKIM_REP_DNS_SUCCESS;
}

/*
**  DKIM_REP_INIT -- initialize an RBL handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new RBL handle suitable for use with other RBL functions, or
**  	NULL on failure.
**  
**  Side effects:
**  	Sudden changes in local density altitude.
*/

/*
**  DKIM_REP_MD5_TO_STRING -- convert an MD5 digest to printable hex
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
dkim_rep_md5_to_string(void *md5, unsigned char *str, size_t len)
{
	int c;
	int out = 0;
	unsigned char *cvt;
	unsigned char digest[MD5_DIGEST_LENGTH];

	assert(md5 != NULL);
	assert(str != NULL);

	if (len < 2 * MD5_DIGEST_LENGTH + 1)
		return -1;

#ifdef USE_GNUTLS
	(void) gnutls_hash_deinit(md5, digest);
#else /* USE_GNUTLS */
	MD5_Final(digest, md5);
#endif /* USE_GNUTLS */

	for (cvt = str, c = 0; c < MD5_DIGEST_LENGTH; c++)
	{
		snprintf((char *) cvt, len, "%02x", digest[c]);
		cvt += 2;
		out += 2;
		len -= 2;
	}

	return out;
}

/*
**  DKIM_REP_STRING_EMPTY -- determine if a string is empty or not
**
**  Parameters:
**  	str -- string to analyze
**
**  Return value:
**  	TRUE iff "str" contained no non-whitespace characters
*/

static _Bool
dkim_rep_string_empty(char *str)
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
**  DKIM_REP_INIT -- initialize an DKIM_REP handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new DKIM_REP handle suitable for use with other DKIM_REP
**  	functions, or NULL on failure.
**  
**  Side effects:
**  	Small but detectable movement of the Indian subcontinent.
*/

DKIM_REP
dkim_rep_init(void *(*caller_mallocf)(void *closure, size_t nbytes),
              void (*caller_freef)(void *closure, void *p),
              void *closure)
{
	DKIM_REP new;

	if (caller_mallocf == NULL)
	{
		new = (DKIM_REP) malloc(sizeof(struct dkim_rep_handle));
	}
	else
	{
		new = (DKIM_REP) caller_mallocf(closure,
		                                sizeof(struct dkim_rep_handle));
	}

	if (new == NULL)
		return NULL;

	memset(new, '\0', sizeof(struct dkim_rep_handle));

	new->dkim_rep_timeout = DKIM_REP_DEFTIMEOUT;
	new->dkim_rep_closure = closure;
	new->dkim_rep_malloc = caller_mallocf;
	new->dkim_rep_free = caller_freef;
	new->dkim_rep_dns_start = dkim_rep_res_query;
	new->dkim_rep_dns_waitreply = dkim_rep_res_waitreply;
	new->dkim_rep_dns_cancel = dkim_rep_res_cancel;
	dkim_rep_setdomain(new, DKIM_REP_DEFROOT);

	return new;
}

/*
**  DKIM_REP_CLOSE -- shut down a DKIM_REP instance
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle to shut down
**
**  Return value:
**  	None.
*/

void
dkim_rep_close(DKIM_REP dr)
{
	assert(dr != NULL);

	if (dr->dkim_rep_free != NULL)
		dr->dkim_rep_free(dr->dkim_rep_closure, dr);
	else
		free(dr);
}

/*
**  DKIM_REP_GETERROR -- return any stored error string from within the
**                       DKIM_REP context handle
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

const u_char *
dkim_rep_geterror(DKIM_REP dr)
{
	assert(dr != NULL);

	return dr->dkim_rep_error;
}

/*
**  DKIM_REP_SETDOMAIN -- declare the DKIM_REP's domain (the query root)
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	qroot -- query root
**
**  Return value:
**  	None (yet).
*/

void
dkim_rep_setdomain(DKIM_REP dr, u_char *qroot)
{
	assert(dr != NULL);
	assert(qroot != NULL);

	strncpy(dr->dkim_rep_qroot, qroot, sizeof dr->dkim_rep_qroot);
	dr->dkim_rep_qroot[sizeof dr->dkim_rep_qroot - 1] = '\0';
}

/*
**  DKIM_REP_QUERY_START -- initiate a query to the DKIM_REP for entries
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	user -- local-part of From:
**  	domain -- domain part of From:
**  	signdomain -- signing domain
**  	qh -- query handle (returned)
**
**  Return value:
**  	DKIM_REP_STAT_INVALID -- dkim_rep_setdomain() was not called,
**                               or "query" was NULL
** 	DKIM_REP_STAT_* -- as defined
*/

DKIM_REP_STAT
dkim_rep_query_start(DKIM_REP dr, u_char *user, u_char *domain,
                     u_char *signdomain, void **qh)
{
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
	int error;
	struct dkim_rep_query *q;
	void *rq;
	char *eq;
	char *e;
#ifdef USE_GNUTLS
	gnutls_hash_hd_t md5_user;
	gnutls_hash_hd_t md5_domain;
	gnutls_hash_hd_t md5_signdomain;
#else /* USE_GNUTLS */
	MD5_CTX md5_user;
	MD5_CTX md5_domain;
	MD5_CTX md5_signdomain;
#endif /* USE_GNUTLS */
	struct timeval timeout;
	unsigned char md5_user_str[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char md5_domain_str[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char md5_signdomain_str[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char ansbuf[MAXPACKET];
	char query[DKIM_REP_MAXHOSTNAMELEN + 1];
	char qname[DKIM_REP_MAXHOSTNAMELEN + 1];

	assert(dr != NULL);
	assert(user != NULL);
	assert(domain != NULL);
	assert(signdomain != NULL);
	assert(qh != NULL);

	q = (struct dkim_rep_query *) malloc(sizeof(struct dkim_rep_query));
	if (q == NULL)
		return DKIM_REP_STAT_ERROR;

	/* hash the values */
	memset(md5_user_str, '\0', sizeof md5_user_str);
#ifdef USE_GNUTLS
	if (gnutls_hash_init(&md5_user, GNUTLS_DIG_MD5) == 0)
		gnutls_hash(md5_user, (void *) user, strlen((char *) user));
#else /* USE_GNUTLS */
	MD5_Init(&md5_user);
	MD5_Update(&md5_user, (void *) user, strlen((char *) user));
#endif /* USE_GNUTLS */
	(void) dkim_rep_md5_to_string(&md5_user, md5_user_str,
	                              sizeof md5_user_str);

	memset(md5_domain_str, '\0', sizeof md5_domain_str);
#ifdef USE_GNUTLS
	if (gnutls_hash_init(&md5_domain, GNUTLS_DIG_MD5) == 0)
	{
		gnutls_hash(md5_domain, (void *) domain,
		            strlen((char *) domain));
	}
#else /* USE_GNUTLS */
	MD5_Init(&md5_domain);
	MD5_Update(&md5_domain, (void *) domain, strlen((char *) domain));
#endif /* USE_GNUTLS */
	(void) dkim_rep_md5_to_string(&md5_domain, md5_domain_str,
	                              sizeof md5_domain_str);

	memset(md5_signdomain_str, '\0', sizeof md5_signdomain_str);
#ifdef USE_GNUTLS
	if (gnutls_hash_init(&md5_signdomain, GNUTLS_DIG_MD5) == 0)
	{
		gnutls_hash(md5_signdomain, (void *) signdomain,
		            strlen((char *) signdomain));
	}
#else /* USE_GNUTLS */
	MD5_Init(&md5_signdomain);
	MD5_Update(&md5_signdomain, (void *) signdomain, strlen(signdomain));
#endif /* USE_GNUTLS */
	(void) dkim_rep_md5_to_string(&md5_signdomain, md5_signdomain_str,
	                              sizeof md5_signdomain_str);

	/* construct the query */
	snprintf(query, sizeof query, "%s.%s.%s.%s", md5_user_str,
	         md5_domain_str, md5_signdomain_str, dr->dkim_rep_qroot);

	/* start the query */
	timeout.tv_sec = dr->dkim_rep_timeout;
	timeout.tv_usec = 0;

	anslen = sizeof ansbuf;

	if (dr->dkim_rep_dns_service == NULL &&
	    dr->dkim_rep_dns_init != NULL &&
	    dr->dkim_rep_dns_init(&dr->dkim_rep_dns_service) != 0)
	{
		snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
		         "failed to initialize resolver");
		return DKIM_REP_STAT_ERROR;
	}

	status = dr->dkim_rep_dns_start(dr->dkim_rep_dns_service, T_TXT,
	                                query, q->drq_buf, sizeof q->drq_buf,
	                                &rq);

	if (status != 0)
	{
		snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
		         "DNS query for '%s' failed", query);
		return DKIM_REP_STAT_ERROR;
	}

	q->drq_qh = rq;

	*qh = q;

	return DKIM_REP_STAT_OK;
}

/*
**  DKIM_REP_QUERY_CHECK -- check for a reply from an active query
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	qh -- query handle (returned)
**  	timeout -- timeout
**  	res -- integer into which to write the result (can be NULL)
**
**  Return value:
** 	DKIM_REP_STAT_* -- as defined
*/

DKIM_REP_STAT
dkim_rep_query_check(DKIM_REP dr, void *qh, struct timeval *timeout,
                     int *res)
{
	int out;
	int c;
	int dnserr;
	int status;
	int n;
	int type;
	int class;
	int qdcount;
	int ancount;
	struct dkim_rep_query *rq;
	char *e;
	char *eq;
	char *p;
	char *eob;
	char *ctx;
	u_char *cp;
	u_char *eom;
	u_char *found = NULL;
	HEADER hdr;
	u_char qname[DKIM_REP_MAXHOSTNAMELEN + 1];
	char buf[BUFRSZ + 1];

	assert(dr != NULL);
	assert(qh != NULL);

	rq = qh;

	status = dr->dkim_rep_dns_waitreply(dr->dkim_rep_dns_service,
	                                    rq->drq_qh, timeout,
	                                    &rq->drq_anslen, &dnserr, NULL);

	if (status == DKIM_REP_DNS_ERROR)
	{
		snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
		         "error during query");
		return DKIM_REP_STAT_ERROR;
	}
	else if (status == DKIM_REP_DNS_NOREPLY)
	{
		return DKIM_REP_STAT_NOREPLY;
	}
	else if (status == DKIM_REP_DNS_EXPIRED)
	{
		return DKIM_REP_STAT_EXPIRED;
	}

	/* set up pointers */
	memcpy(&hdr, rq->drq_buf, sizeof hdr);
	cp = (u_char *) rq->drq_buf + HFIXEDSZ;
	eom = (u_char *) rq->drq_buf + rq->drq_anslen;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		(void) dn_expand((unsigned char *) rq->drq_buf, eom, cp,
		                 (char *) qname, sizeof qname);
 
		if ((n = dn_skipname(cp, eom)) < 0)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "'%s' reply corrupt", qname);
			return DKIM_REP_STAT_ERROR;
		}
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "'%s' reply corrupt", qname);
			return DKIM_REP_STAT_ERROR;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_TXT || class != C_IN)
	{
		snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
		         "'%s' unexpected reply type/class", qname);
		return DKIM_REP_STAT_ERROR;
	}

	if (hdr.rcode == NXDOMAIN)
		return DKIM_REP_STAT_NOTFOUND;

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return DKIM_REP_STAT_NOTFOUND;

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) rq->drq_buf, eom, cp,
		                   (RES_UNC_T) qname, sizeof qname)) < 0)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "'%s' reply corrupt", qname);
			return DKIM_REP_STAT_ERROR;
		}
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "'%s' reply corrupt", qname);
			return DKIM_REP_STAT_ERROR;
		}

		GETSHORT(type, cp);
		GETSHORT(class, cp);

		/* skip the TTL */
		cp += INT32SZ;

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			char chost[DKIM_REP_MAXHOSTNAMELEN + 1];

			n = dn_expand((u_char *) rq->drq_buf, eom, cp,
			              chost, DKIM_REP_MAXHOSTNAMELEN);
			cp += n;
			continue;
		}
		else if (type == T_RRSIG)
		{
			/* get payload length */
			if (cp + INT16SZ > eom)
			{
				snprintf(dr->dkim_rep_error,
				         sizeof dr->dkim_rep_error,
				         "'%s' reply corrupt", qname);
				return DKIM_REP_STAT_ERROR;
			}
			GETSHORT(n, cp);

			cp += n;

			continue;
		}
		else if (type != T_TXT)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "'%s' unexpected reply type/class", qname);
			return DKIM_REP_STAT_ERROR;
		}

		if (found != NULL)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "multiple replies for '%s'", qname);
			return DKIM_REP_STAT_ERROR;
		}

		/* remember where this one started */
		found = cp;

		/* get payload length */
		if (cp + INT16SZ > eom)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "'%s' reply corrupt", qname);
			return DKIM_REP_STAT_ERROR;
		}
		GETSHORT(n, cp);

		/* move forward for now */
		cp += n;
	}

	/* if ancount went below 0, there were no good records */
	if (found == NULL)
	{
		snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
		         "'%s' reply was unresolved CNAME", qname);
		return DKIM_REP_STAT_ERROR;
	}

	/* come back to the one we found */
	cp = found;

	/* get payload length */
	if (cp + INT16SZ > eom)
	{
		snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
		         "'%s' reply corrupt", qname);
		return DKIM_REP_STAT_ERROR;
	}

	GETSHORT(n, cp);

	if (cp + n > eom)
	{
		snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
		         "'%s' reply corrupt", qname);
		return DKIM_REP_STAT_ERROR;
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

	/* parse the result and return it */
	out = 0;
	for (p = strtok_r(buf, ";", &ctx);
	     p != NULL;
	     p = strtok_r(NULL, ";", &ctx))
	{
		eq = strchr(p, '=');
		if (eq == NULL)
			continue;

		if (dkim_rep_string_empty(eq + 1))
			continue;

		*eq = '\0';

		if (strcmp(p, "rep") != 0)
			continue;		/* XXX -- other values? */

		errno = 0;
		out = (int) strtol(eq + 1, &e, 10);
		if (*e != '\0' || errno == EINVAL)
		{
			snprintf(dr->dkim_rep_error, sizeof dr->dkim_rep_error,
			         "invalid reputation '%s'", eq + 1);
			return DKIM_REP_STAT_SYNTAX;
		}

		*res = out;
		break;
	}

	return DKIM_REP_STAT_FOUND;
}

/*
**  DKIM_REP_QUERY_CANCEL -- cancel an open query to the service
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	qh -- query handle
**
**  Return value:
** 	DKIM_REP_STAT_* -- as defined
*/

DKIM_REP_STAT
dkim_rep_query_cancel(DKIM_REP dr, void *qh)
{
	struct dkim_rep_query *rq;

	assert(dr != NULL);
	assert(qh != NULL);

	rq = qh;

	dr->dkim_rep_dns_cancel(dr->dkim_rep_dns_service, rq->drq_qh);

	if (dr->dkim_rep_free != NULL)
		dr->dkim_rep_free(dr->dkim_rep_closure, rq);
	else
		free(rq);

	return DKIM_REP_STAT_OK;
}

/*
**  DKIM_REP_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	None.
*/

void
dkim_rep_settimeout(DKIM_REP dr, u_int timeout)
{
	assert(dr != NULL);

	dr->dkim_rep_timeout = timeout;
}

/*
**  DKIM_REP_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	None.
*/

void
dkim_rep_setcallbackint(DKIM_REP dr, u_int cbint)
{
	assert(dr != NULL);

	dr->dkim_rep_cbint = cbint;
}

/*
**  DKIM_REP_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	None.
*/

void
dkim_rep_setcallbackctx(DKIM_REP dr, void *ctx)
{
	assert(dr != NULL);

	dr->dkim_rep_cbctx = ctx;
}

/*
**  DKIM_REP_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	None.
*/

void
dkim_rep_setdnscallback(DKIM_REP dr, void (*func)(const void *))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_callback = func;
}

/*
**  DKIM_REP_DNS_SET_INIT -- stores a pointer to a resolver init function
**
**  Parameters:
**  	dr -- DKIM_REP library handle
**  	func -- function to use to initialize the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void **srv -- DNS service handle (updated)
*/

void
dkim_rep_dns_set_init(DKIM_REP dr, int (*func)(void **))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_init = func;
}

/*
**  DKIM_REP_DNS_SET_CLOSE -- stores a pointer to a resolver shutdown function
**
**  Parameters:
**  	dr -- DKIM_REP library handle
**  	func -- function to use to close the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns void
**  		void *srv -- DNS service handle
*/

void
dkim_rep_dns_set_close(DKIM_REP dr, void (*func)(void *))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_close = func;
}

/*
**  DKIM_REP_DNS_SET_NSLIST -- stores a pointer to a NS list update function
**
**  Parameters:
**  	dr -- DKIM_REP library handle
**  	func -- function to use to update NS list
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int
**  		void *dns -- DNS service handle
**  		const char *nslist -- comma-separated list of nameservers
*/

void
dkim_rep_dns_set_nslist(DKIM_REP dr, int (*func)(void *, const char *))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_setns = func;
}

/*
**  DKIM_REP_DNS_SET_CONFIG -- stores a pointer to a resolver configuration
**                             update function
**
**  Parameters:
**  	dr -- DKIM_REP library handle
**  	func -- function to use to update resolver configuration
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int
**  		void *dns -- DNS service handle
**  		const char *config -- arbitrary resolver configuration data
*/

void
dkim_rep_dns_set_config(DKIM_REP dr, int (*func)(void *, const char *))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_config = func;
}

/*
**  DKIM_REP_DNS_SET_TRUSTANCHOR -- stores a pointer to a trust anchor update
**                                  function
**
**  Parameters:
**  	dr -- DKIM_REP library handle
**  	func -- function to use to update trust anchor data
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int
**  		void *dns -- DNS service handle
**  		const char *trust -- arbitrary trust anchor data
*/

void
dkim_rep_dns_set_trustanchor(DKIM_REP dr, int (*func)(void *, const char *))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_trustanchor = func;
}

/*
**  DKIM_REP_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                                    query service to be used, returning any
**                                    previous handle
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

void *
dkim_rep_dns_set_query_service(DKIM_REP dr, void *h)
{
	void *old;

	assert(dr != NULL);

	old = dr->dkim_rep_dns_service;

	dr->dkim_rep_dns_service = h;

	return old;
}

/*
**  DKIM_REP_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             dkim_rep_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

void
dkim_rep_dns_set_query_start(DKIM_REP dr, int (*func)(void *, int,
                                                      unsigned char *,
                                                      unsigned char *,
                                                      size_t, void **))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_start = func;
}

/*
**  DKIM_REP_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel
**                                   function
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
**  	func -- function to use to cancel running queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- query handle to be canceled
*/

void
dkim_rep_dns_set_query_cancel(DKIM_REP dr, int (*func)(void *, void *))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_cancel = func;
}

/*
**  DKIM_REP_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a
**                                      DNS reply
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
**  	func -- function to use to wait for a reply
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- handle of query that has completed
**  		struct timeval *timeout -- how long to wait
**  		size_t *bytes -- bytes returned
**  		int *error -- error code returned
**  		int *dnssec -- DNSSEC status returned
*/

void
dkim_rep_dns_set_query_waitreply(DKIM_REP dr, int (*func)(void *, void *,
                                                          struct timeval *,
                                                          size_t *, int *,
                                                          int *))
{
	assert(dr != NULL);

	dr->dkim_rep_dns_waitreply = func;
}
