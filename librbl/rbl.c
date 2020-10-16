/*
**  Copyright (c) 2010-2013, The Trusted Domain Project.  All rights reserved.
*/

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

/* librbl includes */
#include "rbl.h"

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

/* struct rbl_query -- an open RBL query */
struct rbl_query
{
	void *			rq_qh;
	size_t			rq_anslen;
	u_char			rq_buf[HFIXEDSZ + MAXPACKET];
};

/* struct rbl_handle -- an RBL library context */
struct rbl_handle
{
	u_int			rbl_timeout;
	u_int			rbl_cbint;
	void *			rbl_cbctx;
	void *			rbl_closure;
	void *			(*rbl_malloc) (void *closure, size_t nbytes);
	void			(*rbl_free) (void *closure, void *p);
	void			(*rbl_dns_callback) (const void *context);
	void *			rbl_dns_service;
	int			(*rbl_dns_init) (void **srv);
	void			(*rbl_dns_close) (void *srv);
	int			(*rbl_dns_start) (void *srv, int type,
				                  unsigned char *query,
				                  unsigned char *buf,
				                  size_t buflen,
				                  void **qh);
	int			(*rbl_dns_cancel) (void *srv, void *qh);
	int			(*rbl_dns_config) (void *srv,
				                   const char *config);
	int			(*rbl_dns_trustanchor) (void *srv,
				                        const char *trust);
	int			(*rbl_dns_setns) (void *srv, const char *ns);
	int			(*rbl_dns_waitreply) (void *srv,
				                      void *qh,
				                      struct timeval *to,
				                      size_t *bytes,
				                      int *error,
				                      int *dnssec);
	u_char			rbl_qroot[RBL_MAXHOSTNAMELEN + 1];
	u_char			rbl_error[RBL_MAXERRORSTRING + 1];
};

/*
**  Standard UNIX resolver stub functions
*/

struct rbl_res_qh
{
	int		rq_error;
	size_t		rq_buflen;
};

/*
**  RBL_RES_CANCEL -- cancel a pending resolver query
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
rbl_res_cancel(void *srv, void *qh)
{
	if (qh != NULL)
		free(qh);

	return 0;
}

/*
**  RBL_RES_QUERY -- initiate a DNS query
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
**  	An RBL_DNS_* constant.
**
**  Notes:
**  	This is a stub for the stock UNIX resolver (res_) functions, which
**  	are synchronous so no handle needs to be created, so "qh" is set to
**  	"buf".  "buf" is actually populated before this returns (unless
**  	there's an error).
*/

static int
rbl_res_query(void *srv, int type, unsigned char *query, unsigned char *buf,
              size_t buflen, void **qh)
{
	int n;
	int ret;
	struct rbl_res_qh *rq;
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
		return RBL_DNS_ERROR;
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
		return RBL_DNS_ERROR;
	}

#ifdef HAVE_RES_NINIT
	res_nclose(&statp);
#endif /* HAVE_RES_NINIT */

	rq = (struct rbl_res_qh *) malloc(sizeof *rq);
	if (rq == NULL)
		return RBL_DNS_ERROR;

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

	return RBL_DNS_SUCCESS;
}

/*
**  RBL_RES_WAITREPLY -- wait for a reply to a pending query
**
**  Parameters:
**  	srv -- service handle
**  	qh -- query handle
**  	to -- timeout
**  	bytes -- number of bytes in the reply (returned)
**  	error -- error code (returned)
**
**  Return value:
**  	A RBL_DNS_* code.
**
**  Notes:
**  	Since the stock UNIX resolver is synchronous, the reply was completed
** 	before rbl_res_query() returned, and thus this is almost a no-op.
*/

int
rbl_res_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                  int *error, int *dnssec)
{
	struct rbl_res_qh *rq;

	assert(qh != NULL);

	rq = qh;

	if (bytes != NULL)
		*bytes = rq->rq_buflen;
	if (error != NULL)
		*error = rq->rq_error;

	return RBL_DNS_SUCCESS;
}

/*
**  RBL_RES_SETNS -- set nameserver list
**
**  Parameters:
**  	srv -- service handle
**  	nslist -- nameserver list, as a string
**
**  Return value:
**  	0 -- success
**  	!0 -- error
*/

int
rbl_res_nslist(void *srv, const char *nslist)
{
#ifdef HAVE_RES_SETSERVERS
	int nscount = 0;
	char *tmp;
	char *ns;
	char *last = NULL;
	struct sockaddr_in in;
# ifdef AF_INET6
	struct sockaddr_in6 in6;
# endif /* AF_INET6 */
	struct state *res;
	res_sockaddr_union nses[MAXNS];

	assert(srv != NULL);
	assert(nslist != NULL);

	memset(nses, '\0', sizeof nses);

	tmp = strdup(nslist);
	if (tmp == NULL)
		return -1;

	for (ns = strtok_r(tmp, ",", &last);
	     ns != NULL && nscount < MAXNS;
	     ns = strtok_r(NULL, ",", &last)
	{
		memset(&in, '\0', sizeof in);
# ifdef AF_INET6
		memset(&in6, '\0', sizeof in6);
# endif /* AF_INET6 */

		if (inet_pton(AF_INET, ns, (struct in_addr *) &in.sin_addr,
		              sizeof in.sin_addr) == 1)
		{
			in.sin_family= AF_INET;
			in.sin_port = htons(DNSPORT);
			memcpy(&nses[nscount].sin, &in,
			       sizeof nses[nscount].sin);
			nscount++;
		}
# ifdef AF_INET6
		else if (inet_pton(AF_INET6, ns,
		                   (struct in6_addr *) &in6.sin6_addr,
		                   sizeof in6.sin6_addr) == 1)
		{
			in6.sin6_family= AF_INET6;
			in6.sin6_port = htons(DNSPORT);
			memcpy(&nses[nscount].sin6, &in6,
			       sizeof nses[nscount].sin6);
			nscount++;
		}
# endif /* AF_INET6 */
		else
		{
			free(tmp);
			return -1;
		}
	}

	res = srv;
	res_setservers(res, nses, nscount);

	free(tmp);
#endif /* HAVE_RES_SETSERVERS */
	return 0;
}

/*
**  RBL_RES_CLOSE -- shut down the resolver
**
**  Parameters:
**  	srv -- service handle
**
**  Return value:
**  	None.
*/

void
rbl_res_close(void *srv)
{
#ifdef HAVE_RES_NINIT
	struct state *res;

	res = srv;

	res_nclose(res);

	free(res);
#endif /* HAVE_RES_NINIT */
}

/*
**  RBL_INIT -- initialize an RBL handle
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

RBL *
rbl_init(void *(*caller_mallocf)(void *closure, size_t nbytes),
         void (*caller_freef)(void *closure, void *p),
         void *closure)
{
	RBL *new;

	if (caller_mallocf == NULL)
		new = (RBL *) malloc(sizeof(struct rbl_handle));
	else
		new = caller_mallocf(closure, sizeof(struct rbl_handle));

	if (new == NULL)
		return NULL;

	memset(new, '\0', sizeof(struct rbl_handle));

	new->rbl_timeout = RBL_DEFTIMEOUT;
	new->rbl_closure = closure;
	new->rbl_malloc = caller_mallocf;
	new->rbl_free = caller_freef;
	new->rbl_dns_start = rbl_res_query;
	new->rbl_dns_waitreply = rbl_res_waitreply;
	new->rbl_dns_cancel = rbl_res_cancel;
	new->rbl_dns_setns = rbl_res_nslist;
	new->rbl_dns_close = rbl_res_close;

	return new;
}

/*
**  RBL_CLOSE -- shut down a RBL instance
**
**  Parameters:
**  	rbl -- RBL handle to shut down
**
**  Return value:
**  	None.
*/

void
rbl_close(RBL *rbl)
{
	assert(rbl != NULL);

	if (rbl->rbl_dns_service != NULL &&
	    rbl->rbl_dns_close != NULL)
		(void) rbl->rbl_dns_close(rbl->rbl_dns_service);

	if (rbl->rbl_free != NULL)
		rbl->rbl_free(rbl->rbl_closure, rbl);
	else
		free(rbl);
}

/*
**  RBL_GETERROR -- return any stored error string from within the RBL
**                  context handle
**
**  Parameters:
**  	rbl -- RBL handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

const u_char *
rbl_geterror(RBL *rbl)
{
	assert(rbl != NULL);

	return rbl->rbl_error;
}

/*
**  RBL_SETDOMAIN -- declare the RBL's domain (the query root)
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	qroot -- query root
**
**  Return value:
**  	None (yet).
*/

void
rbl_setdomain(RBL *rbl, u_char *qroot)
{
	assert(rbl != NULL);
	assert(qroot != NULL);

	strncpy(rbl->rbl_qroot, qroot, sizeof rbl->rbl_qroot);
	rbl->rbl_qroot[sizeof rbl->rbl_qroot - 1] = '\0';
}

/*
**  RBL_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	None.
*/

void
rbl_settimeout(RBL *rbl, u_int timeout)
{
	assert(rbl != NULL);

	rbl->rbl_timeout = timeout;
}

/*
**  RBL_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	None.
*/

void
rbl_setcallbackint(RBL *rbl, u_int cbint)
{
	assert(rbl != NULL);

	rbl->rbl_cbint = cbint;
}

/*
**  RBL_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	None.
*/

void
rbl_setcallbackctx(RBL *rbl, void *ctx)
{
	assert(rbl != NULL);

	rbl->rbl_cbctx = ctx;
}

/*
**  RBL_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	None.
*/

void
rbl_setdnscallback(RBL *rbl, void (*func)(const void *context))
{
	assert(rbl != NULL);

	rbl->rbl_dns_callback = func;
}

/*
**  RBL_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                               query service to be used, returning any
**                               previous handle
**
**  Parameters:
**  	rbl -- RBL library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

void *
rbl_dns_set_query_service(RBL *rbl, void *h)
{
	void *old;

	assert(rbl != NULL);

	old = rbl->rbl_dns_service;

	rbl->rbl_dns_service = h;

	return old;
}

/*
**  RBL_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	rbl -- RBL library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             rbl_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

void
rbl_dns_set_query_start(RBL *rbl, int (*func)(void *, int,
                                              unsigned char *,
                                              unsigned char *,
                                              size_t, void **))
{
	assert(rbl != NULL);

	rbl->rbl_dns_start = func;
}

/*
**  RBL_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel function
**
**  Parameters:
**  	rbl -- RBL library handle
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
rbl_dns_set_query_cancel(RBL *rbl, int (*func)(void *, void *))
{
	assert(rbl != NULL);

	rbl->rbl_dns_cancel = func;
}

/*
**  RBL_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a DNS reply
**
**  Parameters:
**  	rbl -- RBL library handle
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
rbl_dns_set_query_waitreply(RBL *rbl, int (*func)(void *, void *,
                                                  struct timeval *,
                                                  size_t *, int *,
                                                  int *))
{
	assert(rbl != NULL);

	rbl->rbl_dns_waitreply = func;
}

/*
**  RBL_DNS_SET_NSLIST -- stores a pointer to a NS list update function
**
**  Parameters:
**  	lib -- RBL library handle
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
rbl_dns_set_nslist(RBL *lib, int (*func)(void *, const char *))
{
	assert(lib != NULL);

	if (func != NULL)
		lib->rbl_dns_setns = func;
	else
		lib->rbl_dns_setns = rbl_res_nslist;
}

/*
**  RBL_DNS_SET_CONFIG -- stores a pointer to a resolver configuration update
**                        function
**
**  Parameters:
**  	lib -- RBL library handle
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
rbl_dns_set_config(RBL *lib, int (*func)(void *, const char *))
{
	assert(lib != NULL);

	lib->rbl_dns_config = func;
}

/*
**  RBL_DNS_SET_TRUSTANCHOR -- stores a pointer to a trust anchor update
**                             function
**
**  Parameters:
**  	lib -- RBL library handle
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
rbl_dns_set_trustanchor(RBL *lib, int (*func)(void *, const char *))
{
	assert(lib != NULL);

	lib->rbl_dns_trustanchor = func;
}

/*
**  RBL_DNS_SET_CLOSE -- stores a pointer to a resolver shutdown function
**
**  Parameters:
**  	lib -- RBL library handle
**  	func -- function to use to initialize the resolver
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
rbl_dns_set_close(RBL *lib, void (*func)(void *))
{
	assert(lib != NULL);

	if (func != NULL)
		lib->rbl_dns_close = func;
	else
		lib->rbl_dns_close = rbl_res_close;
}

/*
**  RBL_DNS_SET_INIT -- stores a pointer to a resolver init function
**
**  Parameters:
**  	lib -- RBL library handle
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
rbl_dns_set_init(RBL *lib, int (*func)(void **))
{
	assert(lib != NULL);

	lib->rbl_dns_init = func;
}

/*
**  RBL_DNS_NSLIST -- requests update to a nameserver list
**
**  Parameters:
**  	lib -- RBL library handle
**  	nslist -- comma-separated list of nameservers to use
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

RBL_STAT
rbl_dns_nslist(RBL *lib, const char *nslist)
{
	int status;

	assert(lib != NULL);
	assert(nslist != NULL);

	if (lib->rbl_dns_setns != NULL)
	{
		status = lib->rbl_dns_setns(lib->rbl_dns_service, nslist);
		if (status != 0)
			return RBL_STAT_ERROR;
	}

	return RBL_STAT_OK;
}

/*
**  RBL_DNS_CONFIG -- requests a change to resolver configuration
**
**  Parameters:
**  	lib -- RBL library handle
**  	config -- opaque configuration string
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

RBL_STAT
rbl_dns_config(RBL *lib, const char *config)
{
	int status;

	assert(lib != NULL);
	assert(config != NULL);

	if (lib->rbl_dns_config != NULL)
	{
		status = lib->rbl_dns_config(lib->rbl_dns_service, config);
		if (status != 0)
			return RBL_STAT_ERROR;
	}

	return RBL_STAT_OK;
}

/*
**  RBL_DNS_TRUSTANCHOR -- requests a change to resolver trust anchor data
**
**  Parameters:
**  	lib -- RBL library handle
**  	trust -- opaque trust anchor string
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

RBL_STAT
rbl_dns_trustanchor(RBL *lib, const char *trust)
{
	int status;

	assert(lib != NULL);
	assert(trust != NULL);

	if (lib->rbl_dns_trustanchor != NULL)
	{
		status = lib->rbl_dns_trustanchor(lib->rbl_dns_service, trust);
		if (status != 0)
			return RBL_STAT_ERROR;
	}

	return RBL_STAT_OK;
}

/*
**  RBL_DNS_INIT -- force nameserver (re)initialization
**
**  Parameters:
**  	lib -- RBL library handle
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

RBL_STAT
rbl_dns_init(RBL *lib)
{
	int status;

	assert(lib != NULL);

	if (lib->rbl_dns_service != NULL &&
	    lib->rbl_dns_close != NULL)
		lib->rbl_dns_close(lib->rbl_dns_service);

	lib->rbl_dns_service = NULL;

	if (lib->rbl_dns_init != NULL)
		return lib->rbl_dns_init(&lib->rbl_dns_service);
	else
		return RBL_STAT_OK;
}

/*
**  RBL_QUERY_CANCEL -- cancel an open query to the RBL
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	qh -- query handle
**
**  Return value:
** 	RBL_STAT_* -- as defined
*/

RBL_STAT
rbl_query_cancel(RBL *rbl, void *qh)
{
	struct rbl_query *rq;

	assert(rbl != NULL);
	assert(qh != NULL);

	rq = qh;

	rbl->rbl_dns_cancel(rbl->rbl_dns_service, rq->rq_qh);

	if (rbl->rbl_free != NULL)
		rbl->rbl_free(rbl->rbl_closure, rq);
	else
		free(rq);

	return RBL_STAT_OK;
}

/*
**  RBL_QUERY_START -- initiate a query to the RBL for entries
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	query -- query string
**  	qh -- query handle (returned)
**
**  Return value:
** 	RBL_STAT_* -- as defined
*/

RBL_STAT
rbl_query_start(RBL *rbl, u_char *query, void **qh)
{
	int status;
	struct rbl_query *rq;
	u_char rblquery[RBL_MAXHOSTNAMELEN + 1];

	assert(rbl != NULL);
	assert(query != NULL);
	assert(qh != NULL);

	if (rbl->rbl_qroot[0] == '\0')
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "query root not set");
		return RBL_STAT_INVALID;
	}

	snprintf(rblquery, sizeof rblquery, "%s.%s", query, rbl->rbl_qroot);

	if (rbl->rbl_malloc != NULL)
		rq = rbl->rbl_malloc(rbl->rbl_closure, sizeof(*rq));
	else
		rq = malloc(sizeof(*rq));

	if (rq == NULL)
		return RBL_STAT_NORESOURCE;

	memset(rq, '\0', sizeof *rq);

	if (rbl->rbl_dns_service == NULL &&
	    rbl->rbl_dns_init != NULL &&
	    rbl->rbl_dns_init(&rbl->rbl_dns_service) != 0)
	{
		if (rbl->rbl_free != NULL)
			rbl->rbl_free(rbl->rbl_closure, rq);
		else
			free(rq);

		return RBL_STAT_DNSERROR;
	}

	status = rbl->rbl_dns_start(rbl->rbl_dns_service, T_A, rblquery,
	                            rq->rq_buf, sizeof rq->rq_buf, &rq->rq_qh);

	if (status == 0)
	{
		*qh = rq;
		return RBL_STAT_OK;
	}
	else
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "unable to start query for '%s'", rblquery);
		return RBL_STAT_DNSERROR;
	}
}

/*
**  RBL_QUERY_CHECK -- check for a reply from an active query
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	qh -- query handle (returned)
**  	timeout -- timeout
**  	res -- 32-bit buffer into which to write the result (can be NULL)
**
**  Return value:
** 	RBL_STAT_* -- as defined
*/

RBL_STAT
rbl_query_check(RBL *rbl, void *qh, struct timeval *timeout, uint32_t *res)
{
	int dnserr;
	int status;
	int n;
	int type;
	int class;
	int qdcount;
	int ancount;
	struct rbl_query *rq;
	u_char *cp;
	u_char *eom;
	u_char *found = NULL;
	HEADER hdr;
	u_char qname[RBL_MAXHOSTNAMELEN + 1];

	assert(rbl != NULL);
	assert(qh != NULL);

	rq = qh;

	status = rbl->rbl_dns_waitreply(rbl->rbl_dns_service,
	                                rq->rq_qh, timeout, &rq->rq_anslen,
	                                &dnserr, NULL);

	if (status == RBL_DNS_ERROR)
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "error during query");
		return RBL_STAT_ERROR;
	}
	else if (status == RBL_DNS_NOREPLY)
	{
		return RBL_STAT_NOREPLY;
	}
	else if (status == RBL_DNS_EXPIRED)
	{
		return RBL_STAT_EXPIRED;
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
			snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
			         "'%s' reply corrupt", qname);
			return RBL_STAT_ERROR;
		}
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
			         "'%s' reply corrupt", qname);
			return RBL_STAT_ERROR;
		}
		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_A || class != C_IN)
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "'%s' unexpected reply type/class", qname);
		return RBL_STAT_ERROR;
	}

	/* if NXDOMAIN, return DKIM_STAT_NOKEY */
	if (hdr.rcode == NXDOMAIN)
		return RBL_STAT_NOTFOUND;

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return RBL_STAT_NOTFOUND;

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) rq->rq_buf, eom, cp,
		                   (RES_UNC_T) qname, sizeof qname)) < 0)
		{
			snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
			         "'%s' reply corrupt", qname);
			return RBL_STAT_ERROR;
		}
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
		{
			snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
			         "'%s' reply corrupt", qname);
			return RBL_STAT_ERROR;
		}

		GETSHORT(type, cp);
		GETSHORT(class, cp);

		/* skip the TTL */
		cp += INT32SZ;

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			char chost[RBL_MAXHOSTNAMELEN + 1];

			n = dn_expand((u_char *) rq->rq_buf, eom, cp,
			              chost, RBL_MAXHOSTNAMELEN);
			cp += n;
			continue;
		}
		else if (type == T_RRSIG)
		{
			/* get payload length */
			if (cp + INT16SZ > eom)
			{
				snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
				         "'%s' reply corrupt", qname);
				return RBL_STAT_ERROR;
			}
			GETSHORT(n, cp);

			cp += n;

			continue;
		}
		else if (type != T_A)
		{
			snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
			         "'%s' unexpected reply type/class", qname);
			return RBL_STAT_ERROR;
		}

		if (found != NULL)
		{
			snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
			         "multiple replies for '%s'", qname);
			return RBL_STAT_ERROR;
		}

		/* remember where this one started */
		found = cp;

		/* get payload length */
		if (cp + INT16SZ > eom)
		{
			snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
			         "'%s' reply corrupt", qname);
			return RBL_STAT_ERROR;
		}
		GETSHORT(n, cp);

		/* move forward for now */
		cp += n;
	}

	/* if ancount went below 0, there were no good records */
	if (found == NULL)
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "'%s' reply was unresolved CNAME", qname);
		return RBL_STAT_ERROR;
	}

	/* come back to the one we found */
	cp = found;

	/* get payload length */
	if (cp + INT16SZ > eom)
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "'%s' reply corrupt", qname);
		return RBL_STAT_ERROR;
	}

	GETSHORT(n, cp);
	if (n != sizeof(uint32_t))
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "'%s' reply corrupt", qname);
		return RBL_STAT_ERROR;
	}

	if (cp + n > eom)
	{
		snprintf(rbl->rbl_error, sizeof rbl->rbl_error,
		         "'%s' reply corrupt", qname);
		return RBL_STAT_ERROR;
	}

	/* extract the payload */
	if (res != NULL)
	{
		uint32_t addr;

		GETLONG(addr, cp);

		*res = addr;
	}

	return RBL_STAT_FOUND;
}
