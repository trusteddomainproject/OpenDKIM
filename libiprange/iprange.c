/*
**  Copyright (c) 2010, 2011, The OpenDKIM Project.  All rights reserved.
*/

/* TODO:
** - needs a worker pool that handles all of the various subqueries
**   for a given main query, so the caller only waits on a final result
** - needs support for IPv6
*/

#ifndef lint
static char iprange_c_id[] = "$Id$";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

/* libiprange includes */
#include "iprange.h"

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

/* struct iprange_query -- an open IPRANGE query */
struct iprange_query
{
	void *			rq_qh;
	size_t			rq_anslen;
	u_char			rq_buf[HFIXEDSZ + MAXPACKET];
};

/* struct iprange_handle -- an IPRANGE library context */
struct iprange_handle
{
	u_int			iprange_timeout;
	u_int			iprange_cbint;
	void *			iprange_cbctx;
	void *			iprange_closure;
	void *			(*iprange_malloc) (void *closure,
				                   size_t nbytes);
	void			(*iprange_free) (void *closure, void *p);
	void			(*iprange_dns_callback) (const void *context);
	void *			iprange_dns_service;
	int			(*iprange_dns_start) (void *srv, int type,
				                      unsigned char *query,
				                      unsigned char *buf,
				                      size_t buflen,
				                      void **qh);
	int			(*iprange_dns_cancel) (void *srv, void *qh);
	int			(*iprange_dns_waitreply) (void *srv,
				                          void *qh,
				                          struct timeval *to,
				                          size_t *bytes,
				                          int *error,
				                          int *dnssec);
	u_char			iprange_qroot[IPRANGE_MAXHOSTNAMELEN + 1];
	u_char			iprange_error[IPRANGE_MAXERRORSTRING + 1];
};

/*
**  Standard UNIX resolver stub functions
*/

struct iprange_res_qh
{
	int		rq_error;
	size_t		rq_buflen;
};

/*
**  IPRANGE_RES_CANCEL -- cancel a pending resolver query
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
iprange_res_cancel(void *srv, void *qh)
{
	if (qh != NULL)
		free(qh);

	return 0;
}

/*
**  IPRANGE_RES_QUERY -- initiate a DNS query
**
**  Parameters:
**  	srv -- service handle (ignored)
**  	type -- RR type to query
**  	query -- the question to ask
**  	buf -- where to write the answer
**  	buflen -- bytes at "buf"
** 	qh -- query handle, used with iprange_res_waitreply
**
**  Return value:
**  	An IPRANGE_DNS_* constant.
**
**  Notes:
**  	This is a stub for the stock UNIX resolver (res_) functions, which
**  	are synchronous so no handle needs to be created, so "qh" is set to
**  	"buf".  "buf" is actually populated before this returns (unless
**  	there's an error).
*/

static int
iprange_res_query(void *srv, int type, unsigned char *query,
                  unsigned char *buf, size_t buflen, void **qh)
{
	int n;
	int ret;
	struct iprange_res_qh *rq;
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
		return IPRANGE_DNS_ERROR;
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
		return IPRANGE_DNS_ERROR;
	}

#ifdef HAVE_RES_NINIT
	res_nclose(&statp);
#endif /* HAVE_RES_NINIT */

	rq = (struct iprange_res_qh *) malloc(sizeof *rq);
	if (rq == NULL)
		return IPRANGE_DNS_ERROR;

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

	return IPRANGE_DNS_SUCCESS;
}

/*
**  IPRANGE_RES_WAITREPLY -- wait for a reply to a pending query
**
**  Parameters:
**  	srv -- service handle
**  	qh -- query handle
**  	to -- timeout
**  	bytes -- number of bytes in the reply (returned)
**  	error -- error code (returned)
**
**  Return value:
**  	A IPRANGE_DNS_* code.
**
**  Notes:
**  	Since the stock UNIX resolver is synchronous, the reply was completed
** 	before iprange_res_query() returned, and thus this is almost a no-op.
*/

int
iprange_res_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                      int *error, int *dnssec)
{
	struct iprange_res_qh *rq;

	assert(qh != NULL);

	rq = qh;

	if (bytes != NULL)
		*bytes = rq->rq_buflen;
	if (error != NULL)
		*error = rq->rq_error;

	return IPRANGE_DNS_SUCCESS;
}

/*
**  IPRANGE_INIT -- initialize an IPRANGE handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new IPRANGE RBL handle suitable for use with other IPRANGE RBL
**  	functions, or NULL on failure.
**  
**  Side effects:
**  	Sudden changes in local density altitude.
*/

IPRANGE *
iprange_init(void *(*caller_mallocf)(void *closure, size_t nbytes),
             void (*caller_freef)(void *closure, void *p),
             void *closure)
{
	IPRANGE *new;

	if (caller_mallocf == NULL)
		new = (IPRANGE *) malloc(sizeof(struct iprange_handle));
	else
		new = caller_mallocf(closure, sizeof(struct iprange_handle));

	if (new == NULL)
		return NULL;

	memset(new, '\0', sizeof(struct iprange_handle));

	new->iprange_timeout = IPRANGE_DEFTIMEOUT;
	new->iprange_closure = closure;
	new->iprange_malloc = caller_mallocf;
	new->iprange_free = caller_freef;
	new->iprange_dns_start = iprange_res_query;
	new->iprange_dns_waitreply = iprange_res_waitreply;
	new->iprange_dns_cancel = iprange_res_cancel;

	return new;
}

/*
**  IPRANGE_CLOSE -- shut down a IPRANGE instance
**
**  Parameters:
**  	iprange -- IPRANGE handle to shut down
**
**  Return value:
**  	None.
*/

void
iprange_close(IPRANGE *rbl)
{
	assert(rbl != NULL);

	if (iprange->iprange_free != NULL)
		iprange->iprange_free(iprange->iprange_closure, rbl);
	else
		free(rbl);
}

/*
**  IPRANGE_GETERROR -- return any stored error string from within the IPRANGE
**                  context handle
**
**  Parameters:
**  	iprange -- IPRANGE handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

const u_char *
iprange_geterror(IPRANGE *rbl)
{
	assert(rbl != NULL);

	return iprange->iprange_error;
}

/*
**  IPRANGE_SETDOMAIN -- declare the IPRANGE's domain (the query root)
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	qroot -- query root
**
**  Return value:
**  	None (yet).
*/

void
iprange_setdomain(IPRANGE *rbl, u_char *qroot)
{
	assert(rbl != NULL);
	assert(qroot != NULL);

	strncpy(iprange->iprange_qroot, qroot, sizeof iprange->iprange_qroot);
	iprange->iprange_qroot[sizeof iprange->iprange_qroot - 1] = '\0';
}

/*
**  IPRANGE_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	None.
*/

void
iprange_settimeout(IPRANGE *rbl, u_int timeout)
{
	assert(rbl != NULL);

	iprange->iprange_timeout = timeout;
}

/*
**  IPRANGE_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	None.
*/

void
iprange_setcallbackint(IPRANGE *rbl, u_int cbint)
{
	assert(rbl != NULL);

	iprange->iprange_cbint = cbint;
}

/*
**  IPRANGE_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	None.
*/

void
iprange_setcallbackctx(IPRANGE *rbl, void *ctx)
{
	assert(rbl != NULL);

	iprange->iprange_cbctx = ctx;
}

/*
**  IPRANGE_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	None.
*/

void
iprange_setdnscallback(IPRANGE *rbl, void (*func)(const void *context))
{
	assert(rbl != NULL);

	iprange->iprange_dns_callback = func;
}

/*
**  IPRANGE_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                               query service to be used, returning any
**                               previous handle
**
**  Parameters:
**  	iprange -- IPRANGE library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

void *
iprange_dns_set_query_service(IPRANGE *rbl, void *h)
{
	void *old;

	assert(rbl != NULL);

	old = iprange->iprange_dns_service;

	iprange->iprange_dns_service = h;

	return old;
}

/*
**  IPRANGE_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	iprange -- IPRANGE library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             iprange_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

void
iprange_dns_set_query_start(IPRANGE *rbl, int (*func)(void *, int,
                                              unsigned char *,
                                              unsigned char *,
                                              size_t, void **))
{
	assert(rbl != NULL);

	iprange->iprange_dns_start = func;
}

/*
**  IPRANGE_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel function
**
**  Parameters:
**  	iprange -- IPRANGE library handle
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
iprange_dns_set_query_cancel(IPRANGE *rbl, int (*func)(void *, void *))
{
	assert(rbl != NULL);

	iprange->iprange_dns_cancel = func;
}

/*
**  IPRANGE_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a DNS reply
**
**  Parameters:
**  	iprange -- IPRANGE library handle
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
iprange_dns_set_query_waitreply(IPRANGE *rbl, int (*func)(void *, void *,
                                                          struct timeval *,
                                                          size_t *, int *,
                                                          int *))
{
	assert(rbl != NULL);

	iprange->iprange_dns_waitreply = func;
}

/*
**  IPRANGE_QUERY_CANCEL -- cancel an open query to the IPRANGE
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	qh -- query handle
**
**  Return value:
** 	IPRANGE_STAT_* -- as defined
*/

IPRANGE_STAT
iprange_query_cancel(IPRANGE *rbl, void *qh)
{
	struct iprange_query *rq;

	assert(rbl != NULL);
	assert(qh != NULL);

	rq = qh;

	iprange->iprange_dns_cancel(iprange->iprange_dns_service, rq->rq_qh);

	if (iprange->iprange_free != NULL)
		iprange->iprange_free(iprange->iprange_closure, rq);
	else
		free(rq);

	return IPRANGE_STAT_OK;
}

/*
**  IPRANGE_QUERY_START -- initiate a query to the IPRANGE for entries
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	query -- query string
**  	qh -- query handle (returned)
**
**  Return value:
** 	IPRANGE_STAT_* -- as defined
*/

IPRANGE_STAT
iprange_query_start(IPRANGE *rbl, u_char *query, void **qh)
{
	int status;
	struct iprange_query *rq;
	u_char rblquery[IPRANGE_MAXHOSTNAMELEN + 1];

	assert(rbl != NULL);
	assert(query != NULL);
	assert(qh != NULL);

	if (iprange->iprange_qroot[0] == '\0')
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "query root not set");
		return IPRANGE_STAT_INVALID;
	}

	snprintf(rblquery, sizeof rblquery, "%s.%s", query,
	         iprange->iprange_qroot);

	if (iprange->iprange_malloc != NULL)
	{
		rq = iprange->iprange_malloc(iprange->iprange_closure,
		                             sizeof(*rq));
	}
	else
	{
		rq = malloc(sizeof(*rq));
	}

	if (rq == NULL)
		return IPRANGE_STAT_NORESOURCE;

	memset(rq, '\0', sizeof *rq);

	status = iprange->iprange_dns_start(iprange->iprange_dns_service,
	                                    T_A, rblquery, rq->rq_buf,
	                                    sizeof rq->rq_buf, &rq->rq_qh);

	if (status == 0)
	{
		*qh = rq;
		return IPRANGE_STAT_OK;
	}
	else
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "unable to start query for '%s'", rblquery);
		return IPRANGE_STAT_DNSERROR;
	}
}

/*
**  IPRANGE_QUERY_CHECK -- check for a reply from an active query
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	qh -- query handle (returned)
**  	timeout -- timeout
**  	res -- 32-bit buffer into which to write the result (can be NULL)
**
**  Return value:
** 	IPRANGE_STAT_* -- as defined
*/

IPRANGE_STAT
iprange_query_check(IPRANGE *rbl, void *qh, struct timeval *timeout,
                    uint32_t *res)
{
	int dnserr;
	int status;
	int n;
	int type;
	int class;
	int qdcount;
	int ancount;
	struct iprange_query *rq;
	u_char *cp;
	u_char *eom;
	u_char *found = NULL;
	HEADER hdr;
	u_char qname[IPRANGE_MAXHOSTNAMELEN + 1];

	assert(rbl != NULL);
	assert(qh != NULL);

	rq = qh;

	status = iprange->iprange_dns_waitreply(iprange->iprange_dns_service,
	                                rq->rq_qh, timeout, &rq->rq_anslen,
	                                &dnserr, NULL);

	if (status == IPRANGE_DNS_ERROR)
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "error during query");
		return IPRANGE_STAT_ERROR;
	}
	else if (status == IPRANGE_DNS_NOREPLY)
	{
		return IPRANGE_STAT_NOREPLY;
	}
	else if (status == IPRANGE_DNS_EXPIRED)
	{
		return IPRANGE_STAT_EXPIRED;
	}

	/* set up pointers */
	memcpy(&hdr, rq->rq_buf, sizeof hdr);
	cp = (u_char *) rq->rq_buf + HFIXEDSZ;
	eom = (u_char *) rq->rq_buf + rq->rq_anslen;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		(void) dn_expand((unsigned char *) rq->rq_buf, eom, cp,
		                 (char *) qname, sizeof qname);
 
		if ((n = dn_skipname(cp, eom)) < 0)
		{
			snprintf(iprange->iprange_error,
			         sizeof iprange->iprange_error,
			         "'%s' reply corrupt", qname);
			return IPRANGE_STAT_ERROR;
		}
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			snprintf(iprange->iprange_error,
			         sizeof iprange->iprange_error,
			         "'%s' reply corrupt", qname);
			return IPRANGE_STAT_ERROR;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_A || class != C_IN)
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "'%s' unexpected reply type/class", qname);
		return IPRANGE_STAT_ERROR;
	}

	/* if NXDOMAIN, return DKIM_STAT_NOKEY */
	if (hdr.rcode == NXDOMAIN)
		return IPRANGE_STAT_NOTFOUND;

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return IPRANGE_STAT_NOTFOUND;

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) rq->rq_buf, eom, cp,
		                   (RES_UNC_T) qname, sizeof qname)) < 0)
		{
			snprintf(iprange->iprange_error,
			         sizeof iprange->iprange_error,
			         "'%s' reply corrupt", qname);
			return IPRANGE_STAT_ERROR;
		}
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			snprintf(iprange->iprange_error,
			         sizeof iprange->iprange_error,
			         "'%s' reply corrupt", qname);
			return IPRANGE_STAT_ERROR;
		}

		GETSHORT(type, cp);
		GETSHORT(class, cp);

		/* skip the TTL */
		cp += INT32SZ;

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			char chost[IPRANGE_MAXHOSTNAMELEN + 1];

			n = dn_expand((u_char *) rq->rq_buf, eom, cp,
			              chost, IPRANGE_MAXHOSTNAMELEN);
			cp += n;
			continue;
		}
		else if (type == T_RRSIG)
		{
			/* get payload length */
			if (cp + INT16SZ > eom)
			{
				snprintf(iprange->iprange_error,
				         sizeof iprange->iprange_error,
				         "'%s' reply corrupt", qname);
				return IPRANGE_STAT_ERROR;
			}
			GETSHORT(n, cp);

			cp += n;

			continue;
		}
		else if (type != T_A)
		{
			snprintf(iprange->iprange_error,
			         sizeof iprange->iprange_error,
			         "'%s' unexpected reply type/class", qname);
			return IPRANGE_STAT_ERROR;
		}

		if (found != NULL)
		{
			snprintf(iprange->iprange_error,
			         sizeof iprange->iprange_error,
			         "multiple replies for '%s'", qname);
			return IPRANGE_STAT_ERROR;
		}

		/* remember where this one started */
		found = cp;

		/* get payload length */
		if (cp + INT16SZ > eom)
		{
			snprintf(iprange->iprange_error,
			         sizeof iprange->iprange_error,
			         "'%s' reply corrupt", qname);
			return IPRANGE_STAT_ERROR;
		}
		GETSHORT(n, cp);

		/* move forward for now */
		cp += n;
	}

	/* if ancount went below 0, there were no good records */
	if (found == NULL)
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "'%s' reply was unresolved CNAME", qname);
		return IPRANGE_STAT_ERROR;
	}

	/* come back to the one we found */
	cp = found;

	/* get payload length */
	if (cp + INT16SZ > eom)
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "'%s' reply corrupt", qname);
		return IPRANGE_STAT_ERROR;
	}

	GETSHORT(n, cp);
	if (n != sizeof(uint32_t))
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "'%s' reply corrupt", qname);
		return IPRANGE_STAT_ERROR;
	}

	if (cp + n > eom)
	{
		snprintf(iprange->iprange_error, sizeof iprange->iprange_error,
		         "'%s' reply corrupt", qname);
		return IPRANGE_STAT_ERROR;
	}

	/* extract the payload */
	if (res != NULL)
	{
		uint32_t addr;

		GETLONG(addr, cp);

		*res = addr;
	}

	return IPRANGE_STAT_FOUND;
}
