/*
**  Copyright (c) 2010-2012, The Trusted Domain Project.  All rights reserved.
**
*/

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! REENTRANT */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

/* libopendkim includes */
#include "dkim.h"
#include "dkim-dns.h"

/* OpenDKIM includes */
#include "build-config.h"

/* macros, limits, etc. */
#ifndef MAXPACKET
# define MAXPACKET      8192
#endif /* ! MAXPACKET */

/*
**  Standard UNIX resolver stub functions
*/

struct dkim_res_qh
{
	int		rq_error;
	int		rq_dnssec;
	size_t		rq_buflen;
};

/*
**  DKIM_RES_INIT -- initialize the resolver
**
**  Parameters:
**  	srv -- service handle (returned)
**
**  Return value
**  	0 on success, !0 on failure
*/

int
dkim_res_init(void **srv)
{
#ifdef HAVE_RES_NINIT
	struct __res_state *res;

	res = malloc(sizeof(struct __res_state));
	if (res == NULL)
		return -1;

	memset(res, '\0', sizeof(struct __res_state));

	if (res_ninit(res) != 0)
	{
		free(res);
		return -1;
	}
#ifdef RES_USE_DNSSEC
	res->options |= RES_USE_DNSSEC;
#endif

	*srv = res;

	return 0;
#else /* HAVE_RES_NINIT */
	if (res_init() == 0)
	{
#ifdef RES_USE_DNSSEC
		_res.options |= RES_USE_DNSSEC;
#endif
		*srv = (void *) 0x01;
		return 0;
	}
	else
	{
		return -1;
	}
#endif /* HAVE_RES_NINIT */
}

/*
**  DKIM_RES_CLOSE -- shut down the resolver
**
**  Parameters:
**  	srv -- service handle
**
**  Return value:
**  	None.
*/

void
dkim_res_close(void *srv)
{
#ifdef HAVE_RES_NINIT
	struct __res_state *res;

	res = srv;

	if (res != NULL)
	{
		res_nclose(res);
		free(res);
	}
#endif /* HAVE_RES_NINIT */
}

/*
**  DKIM_RES_CANCEL -- cancel a pending resolver query
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

int
dkim_res_cancel(void *srv, void *qh)
{
	if (qh != NULL)
		free(qh);

	return 0;
}

/*
**  DKIM_RES_QUERY -- initiate a DNS query
**
**  Parameters:
**  	srv -- service handle (ignored)
**  	type -- RR type to query
**  	query -- the question to ask
**  	buf -- where to write the answer
**  	buflen -- bytes at "buf"
** 	qh -- query handle, used with dkim_res_waitreply
**
**  Return value:
**  	0 on success, -1 on error
**
**  Notes:
**  	This is a stub for the stock UNIX resolver (res_) functions, which
**  	are synchronous so no handle needs to be created, so "qh" is set to
**  	"buf".  "buf" is actually populated before this returns (unless
**  	there's an error).
*/

int
dkim_res_query(void *srv, int type, unsigned char *query, unsigned char *buf,
               size_t buflen, void **qh)
{
	int ret;
	struct dkim_res_qh *rq;
#ifdef HAVE_RES_NINIT
	struct __res_state *statp;
#endif /* HAVE_RES_NINIT */
	HEADER *hdr;

#ifdef HAVE_RES_NINIT
	statp = srv;
	ret = res_nquery(statp, (char *) query, C_IN, type, buf, buflen);
#else /* HAVE_RES_NINIT */
	ret = res_query((char *) query, C_IN, type, buf, buflen);
#endif /* HAVE_RES_NINIT */
	if (ret == -1)
		return DKIM_DNS_ERROR;

	rq = (struct dkim_res_qh *) malloc(sizeof *rq);
	if (rq == NULL)
		return DKIM_DNS_ERROR;

	hdr = (HEADER *) buf;
	if (hdr->ad)
		rq->rq_dnssec = DKIM_DNSSEC_SECURE;
	else
		rq->rq_dnssec = DKIM_DNSSEC_INSECURE;
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

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_RES_WAITREPLY -- wait for a reply to a pending query
**
**  Parameters:
**  	srv -- service handle
**  	qh -- query handle
**  	to -- timeout
**  	bytes -- number of bytes in the reply (returned)
**  	error -- error code (returned)
**
**  Return value:
**  	A DKIM_DNS_* code.
**
**  Notes:
**  	Since the stock UNIX resolver is synchronous, the reply was completed
** 	before dkim_res_query() returned, and thus this is almost a no-op.
*/

int
dkim_res_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                   int *error, int *dnssec)
{
	struct dkim_res_qh *rq;

	assert(qh != NULL);

	rq = qh;

	if (bytes != NULL)
		*bytes = rq->rq_buflen;
	if (error != NULL)
		*error = rq->rq_error;
	if (dnssec != NULL)
		*dnssec = rq->rq_dnssec;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_RES_SETNS -- set nameserver list
**
**  Parameters:
**  	srv -- service handle
**  	nslist -- nameserver list, as a string
**
**  Return value:
**  	DKIM_DNS_SUCCESS -- success
**  	DKIM_DNS_ERROR -- error
*/

int
dkim_res_nslist(void *srv, const char *nslist)
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
		return DKIM_DNS_ERROR;

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
			return DKIM_DNS_ERROR;
		}
	}

	res = srv;
	res_setservers(res, nses, nscount);

	free(tmp);
#endif /* HAVE_RES_SETSERVERS */

	return DKIM_DNS_SUCCESS;
}
