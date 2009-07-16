/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dkim_ub_c_id[] = "@(#)$Id: dkim-ub.c,v 1.1 2009/07/16 19:12:04 cm-msk Exp $";
#endif /* !lint */

#ifdef USE_UNBOUND
/* system includes */
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/nameser.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

/* libdkim includes */
#include "dkim-types.h"
#include "util.h"

/* libunbound includes */
#include <unbound.h>

/*
**  DKIM_UNBOUND_CB -- callback to handle result of DNS query
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
dkim_unbound_cb(void *mydata, int err, struct ub_result *result)
{
	int n = 0;
	int c;
	size_t buflen;
	unsigned char *cp;
	unsigned char *p;
	unsigned char *eob;
	u_char *buf;
	struct dkim_unbound_cb_data *ubdata;

	ubdata = (struct dkim_unbound_cb_data *) mydata;
	ubdata->ubd_done = FALSE;
	ubdata->ubd_stat = DKIM_STAT_NOKEY;
	ubdata->ubd_rcode = result->rcode;
	buf = ubdata->ubd_buf;
	buflen = ubdata->ubd_buflen;

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

	if (result->havedata)
	{
		if (!result->nxdomain)
		{
			if (result->rcode == 0)
			{
				cp = result->data[0];
				n = result->len[0];
				ubdata->ubd_stat = DKIM_STAT_OK;
			}
		}

		if (ubdata->ubd_type == T_TXT)
		{
			/* extract the payload */
			memset(buf, '\0', buflen);
			p = buf;
			eob = buf + buflen;
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
		}
	}

	ub_resolve_free(result);
	ubdata->ubd_done = TRUE;
}

/*
**  DKIM_UNBOUND_WAIT -- wait for a reply from libunbound
**
**  Parameters:
**  	dkim -- DKIM handle
**  	ubdata -- pointer to a struct dkim_unbound_cb_data
**
**  Return value:
**  	1 -- success
**  	0 -- timeout
**  	-1 -- error
*/

int
dkim_unbound_wait(DKIM *dkim, struct dkim_unbound_cb_data *ubdata)
{
	DKIM_LIB *lib;
	struct timespec timeout;
	struct timeval now;

	assert(dkim != NULL);
	assert(ubdata != NULL);

	lib = dkim->dkim_libhandle;

	(void) gettimeofday(&now, NULL);

	timeout.tv_sec = now.tv_sec + dkim->dkim_timeout;
	timeout.tv_nsec = now.tv_usec * 1000;

	pthread_mutex_lock(&lib->dkiml_ub_lock);

	for (;;)
	{
		/*
		**  Wait for a signal unless/until:
		**  	a) our request is done
		**  	b) there's nobody polling libunbound for results
		**  	c) we don't want to wait anymore (timeout)
		*/

		while (!ubdata->ubd_done &&
		       lib->dkiml_ub_poller &&
		       !dkim_timespec_past(&timeout))
		{
			(void) pthread_cond_timedwait(&lib->dkiml_ub_ready,
			                              &lib->dkiml_ub_lock,
			                              &timeout);
		}

		if (ubdata->ubd_done)
		{
			/* our request completed */
			pthread_mutex_unlock(&lib->dkiml_ub_lock);
			return 1;
		}
		else if (dkim_timespec_past(&timeout))
		{
			/* our request timed out */
			(void) ub_cancel(lib->dkiml_unbound_ctx,
			                 ubdata->ubd_id);
			pthread_mutex_unlock(&lib->dkiml_ub_lock);
			return 0;
		}
		else
		{
			int status;

			/* nobody's waiting for results, so we will */
			lib->dkiml_ub_poller = TRUE;
			pthread_mutex_unlock(&lib->dkiml_ub_lock);

			/* wait for I/O to be available */
			status = dkim_wait_fd(ub_fd(lib->dkiml_unbound_ctx),
			                      &timeout);

			if (status == 0)
			{
				/* no answer in time */
				pthread_mutex_lock(&lib->dkiml_ub_lock);
				lib->dkiml_ub_poller = FALSE;
				(void) ub_cancel(lib->dkiml_unbound_ctx,
				                 ubdata->ubd_id);
				pthread_cond_signal(&lib->dkiml_ub_ready);
				pthread_mutex_unlock(&lib->dkiml_ub_lock);
				return 0;
			}

			assert(status == 1);
			
			/* process anything pending */
			status = ub_process(lib->dkiml_unbound_ctx);
			if (status != 0)
			{
				/* error during processing */
				pthread_mutex_lock(&lib->dkiml_ub_lock);
				lib->dkiml_ub_poller = FALSE;
				(void) ub_cancel(lib->dkiml_unbound_ctx,
				                 ubdata->ubd_id);
				pthread_cond_signal(&lib->dkiml_ub_ready);
				pthread_mutex_unlock(&lib->dkiml_ub_lock);
				return -1;
			}

			/* tell everyone to check for results */
			pthread_cond_broadcast(&lib->dkiml_ub_ready);

			/* recover the lock so the loop can restart */
			pthread_mutex_lock(&lib->dkiml_ub_lock);

			/* clear the "someone is polling" flag */
			lib->dkiml_ub_poller = FALSE;
		}
	}
}

/*
**  DKIM_UNBOUND_QUEUE -- queue a TXT request for processing by libunbound
**
**  Parameters:
**  	dkim -- DKIM handle
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

int
dkim_unbound_queue(DKIM *dkim, char *name, int type,
                   u_char *buf, size_t buflen,
                   struct dkim_unbound_cb_data *cbdata)
{
	int status;
	DKIM_LIB *lib;

	assert(dkim != NULL);
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
	cbdata->ubd_jobid = dkim->dkim_id;
	cbdata->ubd_type = type;

	lib = dkim->dkim_libhandle;

	status = ub_resolve_async(lib->dkiml_unbound_ctx, name, type,
	                          C_IN, (void *) cbdata, dkim_unbound_cb,
	                          &cbdata->ubd_id);
	if (status != 0)
		return -1;

	return 0;
}

/*
**  DKIM_UNBOUND_INIT -- libunbound-specific initialization of a DKIM_LIB
**                       handle
**
**  Parameters:
**  	lib -- DKIM_LIB handle
**
**  Return value:
**  	0 -- success
**  	-1 -- failure
*/

int
dkim_unbound_init(DKIM_LIB *lib)
{
	assert(lib != NULL);

	lib->dkiml_unbound_ctx = ub_ctx_create();
	if (lib->dkiml_unbound_ctx == NULL)
		return -1;

	/* suppress debug output */
	(void) ub_ctx_debugout(lib->dkiml_unbound_ctx, NULL);

	/* set for asynchronous operation */
	ub_ctx_async(lib->dkiml_unbound_ctx, TRUE);

	lib->dkiml_ub_poller = FALSE;

	pthread_mutex_init(&lib->dkiml_ub_lock, NULL);
	pthread_cond_init(&lib->dkiml_ub_ready, NULL);

	return 0;
}

/*
**  DKIM_UNBOUND_CLOSE -- shut down a libunbound context
**
**  Parameters:
**  	lib -- DKIM_LIB handle
**
**  Return value:
**  	0 -- success
**  	-1 -- failure
*/

int
dkim_unbound_close(DKIM_LIB *lib)
{
	assert(lib != NULL);

	if (lib->dkiml_unbound_ctx != NULL)
		ub_ctx_delete(lib->dkiml_unbound_ctx);

	return 0;
}

/*
**  DKIM_UNBOUND_ADD_TRUSTANCHOR -- add a trust anchor file to a
**                                  libunbound context
**
**  Parameters:
**  	lib -- DKIM library
**  	file -- path to add
**
**  Return value:
**  	0 -- success
**  	-1 -- error
*/

int
dkim_unbound_add_trustanchor(DKIM_LIB *lib, char *file)
{
	int status;

	assert(lib != NULL);
	assert(file != NULL);

	status = ub_ctx_add_ta_file(lib->dkiml_unbound_ctx, file);

	return (status == 0 ? 0 : -1);
}
#endif /* USE_UNBOUND */
