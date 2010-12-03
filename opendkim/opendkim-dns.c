/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char opendkim_dns_c_id[] = "@(#)$Id: opendkim-dns.c,v 1.7.10.2 2010/10/28 04:28:04 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>

/* libopendkim includes */
#include <dkim.h>

#ifdef USE_UNBOUND
/* libunbound includes */
# include <unbound.h>
#endif /* USE_UNBOUND */

#ifdef USE_ARLIB
/* libar includes */
# include <ar.h>

# define MAXCNAMEDEPTH	3
#endif /* USE_ARLIB */

/* opendkim includes */
#include "opendkim-dns.h"
#include "util.h"

/* macros */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */
#ifndef MIN
# define MIN(x,y)	((x) < (y) ? (x) : (y))
#endif /* ! MIN */

#ifdef USE_UNBOUND
/* struct dkimf_unbound -- unbound context */
struct dkimf_unbound
{
	_Bool			ub_poller;
	struct ub_ctx *		ub_ub;
	pthread_mutex_t		ub_lock;
	pthread_cond_t		ub_ready;
};

/* struct dkimf_unbound_cb_data -- libunbound callback data */
struct dkimf_unbound_cb_data
{
	int			ubd_done;
	int			ubd_rcode;
	int			ubd_id;
	int			ubd_type;
	int			ubd_result;
	DKIM_STAT		ubd_stat;
	size_t			ubd_buflen;
	u_char *		ubd_buf;
};

/*
**  DKIMF_UNBOUND_CB -- callback to handle result of DNS query
**
**  Parameters:
**  	mydata -- structure to return data to DKIM_GET_KEY_DNS
**  	err -- error code from unbound resolver
**  	result -- result of DNS query
**
**  Return value:
**  	None.
*/

static void
dkimf_unbound_cb(void *mydata, int err, struct ub_result *result)
{
	int n = 0;
	int c;
	unsigned char *cp;
	unsigned char *p;
	unsigned char *eob;
	struct dkimf_unbound_cb_data *ubdata;

	ubdata = (struct dkimf_unbound_cb_data *) mydata;
	ubdata->ubd_done = FALSE;
	ubdata->ubd_stat = DKIM_STAT_NOKEY;
	ubdata->ubd_rcode = result->rcode;
	memcpy(ubdata->ubd_buf, result->answer_packet,
	       MIN(ubdata->ubd_buflen, result->answer_len));
	ubdata->ubd_buflen = result->answer_len;

	if (err != 0)
	{
		ubdata->ubd_stat = DKIM_STAT_INTERNAL;
		return;
	}

	/*
	**  Check whether reply is either secure or insecure.  If bogus,
	**  treat as if no key exists.
	*/

	if (result->secure)
	{
		ubdata->ubd_result = DKIM_DNSSEC_SECURE;
	}
	else if (result->bogus)
	{
		/* result was bogus */
		ubdata->ubd_result = DKIM_DNSSEC_BOGUS;
		return;
	}
	else
	{ 
		ubdata->ubd_result = DKIM_DNSSEC_INSECURE;
	}

	if (result->havedata && !result->nxdomain && result->rcode == NOERROR)
		ubdata->ubd_stat = DKIM_STAT_OK;

	ub_resolve_free(result);

	ubdata->ubd_done = TRUE;
}

/*
**  DKIMF_UNBOUND_WAIT -- wait for a reply from libunbound
**
**  Parameters:
**  	ub -- unbound handle
**  	ubdata -- pointer to a struct dkimf_unbound_cb_data
**  	to -- timeout (or NULL)
**
**  Return value:
**  	1 -- success
**  	0 -- timeout
**  	-1 -- error
*/

static int
dkimf_unbound_wait(struct dkimf_unbound *ub,
                   struct dkimf_unbound_cb_data *ubdata,
                   struct timeval *to)
{
	struct timespec timeout;
	struct timeval now;

	assert(ub != NULL);
	assert(ubdata != NULL);

	if (to != NULL)
	{
		(void) gettimeofday(&now, NULL);

		timeout.tv_sec = now.tv_sec + to->tv_sec;
		timeout.tv_nsec = now.tv_usec * 1000;
		timeout.tv_nsec += (1000 * to->tv_usec);
		if (timeout.tv_nsec > 1000000000)
		{
			timeout.tv_sec += (timeout.tv_nsec / 1000000000);
			timeout.tv_nsec = timeout.tv_nsec % 1000000000;
		}
	}

	pthread_mutex_lock(&ub->ub_lock);

	for (;;)
	{
		/*
		**  Wait for a signal unless/until:
		**  	a) our request is done
		**  	b) there's nobody polling libunbound for results
		**  	c) we don't want to wait anymore (timeout)
		*/

		if (to != NULL)
		{
			while (!ubdata->ubd_done && ub->ub_poller &&
			       !dkimf_timespec_past(&timeout))
			{
				(void) pthread_cond_timedwait(&ub->ub_ready,
				                              &ub->ub_lock,
				                              &timeout);
			}
		}
		else
		{
			while (!ubdata->ubd_done && ub->ub_poller)
			{
				(void) pthread_cond_wait(&ub->ub_ready,
				                         &ub->ub_lock);
			}
		}

		if (ubdata->ubd_done)
		{
			/* our request completed */
			pthread_mutex_unlock(&ub->ub_lock);
			return 1;
		}
		else if (to != NULL && dkimf_timespec_past(&timeout))
		{
			/* our request timed out */
			pthread_mutex_unlock(&ub->ub_lock);
			return 0;
		}
		else
		{
			int status;

			/* nobody's waiting for results, so we will */
			ub->ub_poller = TRUE;
			pthread_mutex_unlock(&ub->ub_lock);

			/* wait for I/O to be available */
			status = dkimf_wait_fd(ub_fd(ub->ub_ub),
			                       to == NULL ? NULL : &timeout);

			if (status == 0)
			{
				/* no answer in time */
				pthread_mutex_lock(&ub->ub_lock);
				ub->ub_poller = FALSE;
				pthread_cond_signal(&ub->ub_ready);
				pthread_mutex_unlock(&ub->ub_lock);
				return 0;
			}

			assert(status == 1);
			
			/* process anything pending */
			status = ub_process(ub->ub_ub);
			if (status != 0)
			{
				/* error during processing */
				pthread_mutex_lock(&ub->ub_lock);
				ub->ub_poller = FALSE;
				pthread_cond_signal(&ub->ub_ready);
				pthread_mutex_unlock(&ub->ub_lock);
				return -1;
			}

			/* tell everyone to check for results */
			pthread_cond_broadcast(&ub->ub_ready);

			/* recover the lock so the loop can restart */
			pthread_mutex_lock(&ub->ub_lock);

			/* clear the "someone is polling" flag */
			ub->ub_poller = FALSE;
		}
	}
}

/*
**  DKIMF_UNBOUND_QUEUE -- queue a request for processing by libunbound
**
**  Parameters:
**  	ub -- unbound context
**  	name -- name to query
**  	type -- record type to request
**  	buf -- where to write the result
**  	buflen -- bytes available at "buf"
**  	cbdata -- callback data structure to use
**
**  Return value:
**  	0 -- success
**  	-1 -- error
*/

static int
dkimf_unbound_queue(struct dkimf_unbound *ub, char *name, int type,
                    u_char *buf, size_t buflen,
                    struct dkimf_unbound_cb_data *cbdata)
{
	int status;

	assert(ub != NULL);
	assert(name != NULL);
	assert(buf != NULL);
	assert(buflen > 0);
	assert(cbdata != NULL);

	cbdata->ubd_done = FALSE;
	cbdata->ubd_buf = buf;
	cbdata->ubd_buflen = buflen;
	cbdata->ubd_stat = DKIM_STAT_OK;
	cbdata->ubd_result = DKIM_DNSSEC_UNKNOWN;
	cbdata->ubd_rcode = NOERROR;
	cbdata->ubd_type = type;

	status = ub_resolve_async(ub->ub_ub, name, type, C_IN,
	                          (void *) cbdata, dkimf_unbound_cb,
	                          &cbdata->ubd_id);
	if (status != 0)
		return -1;

	return 0;
}

/*
**  DKIMF_UB_CANCEL -- function passed to libopendkim to handle cancel requests
**
**  Parameters:
**  	srv -- service handle
**  	q -- query handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_ub_cancel(void *srv, void *q)
{
	struct dkimf_unbound *ub;
	struct dkimf_unbound_cb_data *ubdata;

	assert(srv != NULL);
	assert(q != NULL);

	ub = (struct dkimf_unbound *) srv;
	ubdata = (struct dkimf_unbound_cb_data *) q;

	(void) ub_cancel(ub->ub_ub, ubdata->ubd_id);

	free(q);

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_UB_QUERY -- function passed to libopendkim to handle new requests
**
**  Parameters:
**  	srv -- service handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_ub_query(void *srv, int type, unsigned char *query,
               unsigned char *buf, size_t buflen, void **qh)
{
	int status;
	struct dkimf_unbound *ub;
	struct dkimf_unbound_cb_data *ubdata;

	assert(srv != NULL);
	assert(query != NULL);
	assert(buf != NULL);
	assert(qh != NULL);

	ub = (struct dkimf_unbound *) srv;

	ubdata = (struct dkimf_unbound_cb_data *) malloc(sizeof *ubdata);
	if (ubdata == NULL)
		return DKIM_DNS_ERROR;

	status = dkimf_unbound_queue(ub, (char *) query, type, buf, buflen,
	                             ubdata);
	if (status != 0)
	{
		free(ubdata);
		return DKIM_DNS_ERROR;
	}

	*qh = ubdata;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_UB_WAITREPLY -- function passed to libopendkim to handle
**                        wait requests
**
**  Parameters:
**  	srv -- service handle
**  	q -- query handle
**  	to -- wait timeout
**  	bytes -- bytes (returned)
**  	error -- error code (returned)
**  	dnssec -- DNSSEC status (returned)
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_ub_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                   int *error, int *dnssec)
{
	int status;
	struct dkimf_unbound *ub;
	struct dkimf_unbound_cb_data *ubdata;

	assert(srv != NULL);
	assert(qh != NULL);

	ub = (struct dkimf_unbound *) srv;
	ubdata = (struct dkimf_unbound_cb_data *) qh;

	status = dkimf_unbound_wait(ub, ubdata, to);
	if (status == 1 || status == -1)
	{
		if (dnssec != NULL)
			*dnssec = ubdata->ubd_result;
		if (bytes != NULL)
			*bytes = ubdata->ubd_buflen;
		if (error != NULL && status == -1)
			*error = status;	/* XXX -- improve this */
	}

	if (status == 0)
		return DKIM_DNS_NOREPLY;
	else if (status == 1)
		return DKIM_DNS_SUCCESS;
	else
		return DKIM_DNS_ERROR;
}

/* =========================== PUBLIC FUNCTIONS =========================== */

/*
**  DKIMF_UNBOUND_INIT -- set up a libunbound context and other data
**
**  Parameters:
**  	ub -- unbound context (returned)
**
**  Return value:
**  	0 -- success
**  	-1 -- failure
*/

int
dkimf_unbound_init(struct dkimf_unbound **ub)
{
	struct dkimf_unbound *out;

	assert(ub != NULL);

	out = (struct dkimf_unbound *) malloc(sizeof *out);
	if (out == NULL)
		return -1;

	out->ub_ub = ub_ctx_create();
	if (out->ub_ub == NULL)
	{
		free(out);
		return -1;
	}

	/* suppress debug output */
	(void) ub_ctx_debugout(out->ub_ub, NULL);

	/* set for asynchronous operation */
	ub_ctx_async(out->ub_ub, TRUE);

	out->ub_poller = FALSE;

	pthread_mutex_init(&out->ub_lock, NULL);
	pthread_cond_init(&out->ub_ready, NULL);

	*ub = out;

	return 0;
}

/*
**  DKIMF_UNBOUND_CLOSE -- shut down a libunbound context
**
**  Parameters:
**  	ub -- unbound context
**
**  Return value:
**  	0 -- success
**  	-1 -- failure
*/

int
dkimf_unbound_close(struct dkimf_unbound *ub)
{
	assert(ub != NULL);

	ub_ctx_delete(ub->ub_ub);
	pthread_mutex_destroy(&ub->ub_lock);
	pthread_cond_destroy(&ub->ub_ready);

	return 0;
}

# ifdef _FFR_RBL
/*
**  DKIMF_RBL_UNBOUND_SETUP -- connect libunbound to librbl
**
**  Parameters:
**  	rbl -- librbl handle
**  	ub -- dkimf_unbound handle to use
**
**  Return value:
**  	0 on success, -1 on failure
*/

int
dkimf_rbl_unbound_setup(RBL *rbl, struct dkimf_unbound *ub)
{
	assert(rbl != NULL);
	assert(ub != NULL);

	(void) rbl_dns_set_query_service(rbl, ub);
	(void) rbl_dns_set_query_start(rbl, dkimf_ub_query);
	(void) rbl_dns_set_query_cancel(rbl, dkimf_ub_cancel);
	(void) rbl_dns_set_query_waitreply(rbl, dkimf_ub_waitreply);

	return 0;
}
# endif /* _FFR_RBL */

/*
**  DKIMF_UNBOUND_SETUP -- connect libunbound to libopendkim
**
**  Parameters:
**  	lib -- libopendkim handle
**  	ub -- dkimf_unbound handle to use
**
**  Return value:
**  	0 on success, -1 on failure
*/

int
dkimf_unbound_setup(DKIM_LIB *lib, struct dkimf_unbound *ub)
{
	assert(lib != NULL);
	assert(ub != NULL);

	(void) dkim_dns_set_query_service(lib, ub);
	(void) dkim_dns_set_query_start(lib, dkimf_ub_query);
	(void) dkim_dns_set_query_cancel(lib, dkimf_ub_cancel);
	(void) dkim_dns_set_query_waitreply(lib, dkimf_ub_waitreply);

	return 0;
}

/*
**  DKIMF_UNBOUND_ADD_TRUSTANCHOR -- add a trust anchor file to a
**                                   libunbound context
**
**  Parameters:
**  	ub -- libunbound context
**  	file -- path to add
**
**  Return value:
**  	0 -- success
**  	-1 -- error
*/

int
dkimf_unbound_add_trustanchor(struct dkimf_unbound *ub, char *file)
{
	int status;

	assert(ub != NULL);
	assert(file != NULL);

	status = ub_ctx_add_ta_file(ub->ub_ub, file);

	return (status == 0 ? 0 : -1);
}
#endif /* USE_UNBOUND */

#ifdef USE_ARLIB
/*
**  DKIMF_AR_CANCEL -- function passed to libopendkim to handle cancel
**                     requests
**
**  Parameters:
**  	srv -- service handle
**  	q -- query handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_ar_cancel(void *srv, void *q)
{
	AR_LIB ar;
	AR_QUERY arq;

	assert(srv != NULL);
	assert(q != NULL);

	ar = (AR_LIB) srv;
	arq = (AR_QUERY) q;

	(void) ar_cancelquery(ar, arq);

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_AR_QUERY -- function passed to libopendkim to handle new requests
**
**  Parameters:
**  	srv -- service handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_ar_query(void *srv, int type, unsigned char *query,
               unsigned char *buf, size_t buflen, void **qh)
{
	AR_LIB ar;
	AR_QUERY q;

	assert(srv != NULL);
	assert(query != NULL);
	assert(buf != NULL);
	assert(qh != NULL);

	ar = (AR_LIB) srv;

	q = ar_addquery(ar, (char *) query, C_IN, type, MAXCNAMEDEPTH,
	                buf, buflen, (int *) NULL, (struct timeval *) NULL);
	if (q == NULL)
		return DKIM_DNS_ERROR;

	*qh = (void *) q;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_AR_WAITREPLY -- function passed to libopendkim to handle
**                        wait requests
**
**  Parameters:
**  	srv -- service handle
**  	q -- query handle
**  	to -- wait timeout
**  	bytes -- bytes (returned)
**  	error -- error code (returned)
**  	dnssec -- DNSSEC status (returned)
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_ar_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                   int *error, int *dnssec)
{
	int status;
	size_t r;
	AR_LIB ar;
	AR_QUERY q;

	assert(srv != NULL);
	assert(qh != NULL);

	ar = (AR_LIB) srv;
	q = (AR_QUERY) qh;

	status = ar_waitreply(ar, q, &r, to);
	if (status == 0)
	{
		if (dnssec != NULL)
			*dnssec = DKIM_DNSSEC_UNKNOWN;
		if (bytes != NULL)
			*bytes = r;
	}
	else
	{
		if (error != NULL)
			*error = errno;
	}

	if (status == AR_STAT_SUCCESS)
		return DKIM_DNS_SUCCESS;
	else if (status == AR_STAT_NOREPLY)
		return DKIM_DNS_NOREPLY;
	else
		return DKIM_DNS_ERROR;
}

/* =========================== PUBLIC FUNCTIONS =========================== */

# ifdef _FFR_RBL
/*
**  DKIMF_RBL_ARLIB_SETUP -- connect libar to librbl
**
**  Parameters:
**  	rbl -- librbl handle
**  	libar -- AR_LIB handle
**
**  Return value:
**  	0 on success, -1 on failure
*/

int
dkimf_rbl_arlib_setup(RBL *rbl, AR_LIB ar)
{
	assert(rbl != NULL);
	assert(ar != NULL);

	(void) rbl_dns_set_query_service(rbl, ar);
	(void) rbl_dns_set_query_start(rbl, dkimf_ar_query);
	(void) rbl_dns_set_query_cancel(rbl, dkimf_ar_cancel);
	(void) rbl_dns_set_query_waitreply(rbl, dkimf_ar_waitreply);

	return 0;
}
# endif /* _FFR_RBL */

/*
**  DKIMF_ARLIB_SETUP -- connect libar to libopendkim
**
**  Parameters:
**  	lib -- libopendkim handle
**  	libar -- AR_LIB handle
**
**  Return value:
**  	0 on success, -1 on failure
*/

int
dkimf_arlib_setup(DKIM_LIB *lib, AR_LIB ar)
{
	assert(lib != NULL);
	assert(ar != NULL);

	(void) dkim_dns_set_query_service(lib, ar);
	(void) dkim_dns_set_query_start(lib, dkimf_ar_query);
	(void) dkim_dns_set_query_cancel(lib, dkimf_ar_cancel);
	(void) dkim_dns_set_query_waitreply(lib, dkimf_ar_waitreply);

	return 0;
}
#endif /* USE_ARLIB */
