/*
**  Copyright (c) 2010-2012, The OpenDKIM Project.  All rights reserved.
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
	int n;
	int ret;
	struct dkim_res_qh *rq;
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
		return DKIM_DNS_ERROR;
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
		return DKIM_DNS_ERROR;
	}

#ifdef HAVE_RES_NINIT
	res_nclose(&statp);
#endif /* HAVE_RES_NINIT */

	rq = (struct dkim_res_qh *) malloc(sizeof *rq);
	if (rq == NULL)
		return DKIM_DNS_ERROR;

	rq->rq_dnssec = DKIM_DNSSEC_UNKNOWN;
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
