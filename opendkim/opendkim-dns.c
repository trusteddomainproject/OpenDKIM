/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2014, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <resolv.h>
#include <errno.h>

/* libopendkim includes */
#include <dkim.h>

#ifdef USE_UNBOUND
/* libunbound includes */
# include <unbound.h>
#endif /* USE_UNBOUND */

#ifdef _FFR_RBL
/* librbl includes */
# include <rbl.h>
#endif /* _FFR_RBL */

#ifdef _FFR_VBR
/* libvbr includes */
# include <vbr.h>
#endif /* _FFR_VBR */

/* opendkim includes */
#include "opendkim-dns.h"
#include "opendkim-db.h"
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

#define	BUFRSZ			1024
#define	MAXPACKET		8192

/* struct dkimf_fquery -- a file-based DNS query */
struct dkimf_fquery
{
	unsigned char *		fq_rbuf;
	size_t			fq_rbuflen;
	size_t			fq_qlen;
	unsigned char		fq_qbuf[MAXPACKET];
};

#ifdef USE_UNBOUND
/* struct dkimf_unbound -- unbound context */
struct dkimf_unbound
{
	_Bool			ub_poller;
	struct ub_ctx *		ub_ub;
	pthread_mutex_t		ub_lock;
	pthread_mutex_t		ub_config_lock;
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
	const char *		ubd_strerror;
};
#endif /* USE_UNBOUND */

/*
**  DKIMF_DNS_TRUSTANCHOR -- advise the DKIM library of new trust anchor data
**
**  Parameters:
**  	lib -- DKIM library handle
**  	trust -- trust anchor data
**
**  Return value:
**  	DKIM_DNS_SUCCESS or DKIM_DNS_ERROR
*/

int
dkimf_dns_trustanchor(DKIM_LIB *lib, const char *trust)
{
	assert(lib != NULL);
	assert(trust != NULL);

	return dkim_dns_trustanchor(lib, trust);
}

/*
**  DKIMF_DNS_SETNAMESERVERS -- advise the DKIM library of new nameservers
**
**  Parameters:
**  	lib -- DKIM library handle
**  	nslist -- nameserver list
**
**  Return value:
**  	DKIM_DNS_SUCCESS or DKIM_DNS_ERROR
*/

int
dkimf_dns_setnameservers(DKIM_LIB *lib, const char *nslist)
{
	assert(lib != NULL);
	assert(nslist != NULL);

	return dkim_dns_nslist(lib, nslist);
}

/*
**  DKIMF_DNS_CONFIG -- pass arbitrary configuration to the resolver
**
**  Parameters:
**  	lib -- DKIM library handle
**  	config -- resolver configuration data
**
**  Return value:
**  	DKIM_DNS_SUCCESS or DKIM_DNS_ERROR
*/

int
dkimf_dns_config(DKIM_LIB *lib, const char *config)
{
	assert(lib != NULL);
	assert(config != NULL);

	return dkim_dns_config(lib, config);
}

#ifdef USE_UNBOUND
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
	struct dkimf_unbound_cb_data *ubdata;

	ubdata = (struct dkimf_unbound_cb_data *) mydata;

	if (err != 0)
	{
		ubdata->ubd_done = TRUE;
		ubdata->ubd_stat = DKIM_STAT_INTERNAL;
		ubdata->ubd_strerror = ub_strerror(err);
		return;
	}

	ubdata->ubd_done = FALSE;
	ubdata->ubd_stat = DKIM_STAT_NOKEY;
	ubdata->ubd_rcode = result->rcode;
	memcpy(ubdata->ubd_buf, result->answer_packet,
	       MIN(ubdata->ubd_buflen, result->answer_len));
	ubdata->ubd_buflen = result->answer_len;

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
		ub_resolve_free(result);
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

			/* recover the lock so the loop can restart */
			pthread_mutex_lock(&ub->ub_lock);

			/* tell everyone to check for results */
			pthread_cond_broadcast(&ub->ub_ready);

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
**  DKIMF_UB_TRUSTANCHOR -- add a trust anchor file to a libunbound context
**
**  Parameters:
**  	srv -- service handle
**  	file -- path to add
**
**  Return value:
**  	0 -- success
**  	-1 -- error
*/

int
dkimf_ub_trustanchor(void *srv, const char *file)
{
	int status;
	struct dkimf_unbound *ub;

	assert(srv != NULL);
	assert(file != NULL);

	ub = srv;

	status = ub_ctx_add_ta_file(ub->ub_ub, (char *) file);

	return (status == 0 ? 0 : -1);
}


/*
**  DKIMF_UB_CONFIG -- add a configuration file to a libunbound context
**
**  Parameters:
**  	srv -- void service handle
**  	file -- path to add
**
**  Return value:
**  	0 -- success
**  	-1 -- error
*/

int
dkimf_ub_config(void *srv, const char *file)
{
	int status;
	struct dkimf_unbound *ub;

	assert(srv != NULL);
	assert(file != NULL);

	ub = srv;

	pthread_mutex_lock(&ub->ub_config_lock);
	status = ub_ctx_config(ub->ub_ub, (char *) file);
	pthread_mutex_unlock(&ub->ub_config_lock);

	return (status == 0 ? 0 : -1);
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
	memset(ubdata, '\0', sizeof *ubdata);

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
		return DKIM_DNS_EXPIRED;
	else if (status == 1)
		return DKIM_DNS_SUCCESS;
	else
		return DKIM_DNS_ERROR;
}

/* =========================== PUBLIC FUNCTIONS =========================== */

/*
**  DKIMF_UB_INIT -- set up a libunbound context and other data
**
**  Parameters:
**  	ub -- unbound context (returned)
**
**  Return value:
**  	DKIM_DNS_SUCCESS -- success
**  	DKIM_DNS_ERROR -- failure
*/

int
dkimf_ub_init(void **ub)
{
	struct dkimf_unbound *out;

	assert(ub != NULL);

	out = (struct dkimf_unbound *) malloc(sizeof *out);
	if (out == NULL)
		return DKIM_DNS_ERROR;

	out->ub_ub = ub_ctx_create();
	if (out->ub_ub == NULL)
	{
		free(out);
		return DKIM_DNS_ERROR;
	}

	/* suppress debug output */
	(void) ub_ctx_debugout(out->ub_ub, NULL);

	/* set for asynchronous operation */
	ub_ctx_async(out->ub_ub, TRUE);

	out->ub_poller = FALSE;

	pthread_mutex_init(&out->ub_lock, NULL);
	pthread_mutex_init(&out->ub_config_lock, NULL);
	pthread_cond_init(&out->ub_ready, NULL);

	*ub = out;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_UB_CLOSE -- shut down a libunbound context
**
**  Parameters:
**  	ub -- unbound context
**
**  Return value:
**  	0 -- success
**  	-1 -- failure
*/

void
dkimf_ub_close(void *srv)
{
	struct dkimf_unbound *ub;

	assert(srv != NULL);

	ub = srv;

	ub_ctx_delete(ub->ub_ub);

	pthread_mutex_destroy(&ub->ub_lock);
	pthread_mutex_destroy(&ub->ub_config_lock);
	pthread_cond_destroy(&ub->ub_ready);

	free(srv);
}

/*
**  DKIMF_UB_NSLIST -- set nameserver list
**
**  Parameters:
**  	srv -- unbound service handle (as a void *)
**  	nslist -- nameserver list
**
**  Return value:
**  	DKIM_DNS_SUCCESS or DKIM_DNS_ERROR
*/

int
dkimf_ub_nslist(void *srv, const char *nslist)
{
	char *cp;
	char *p;
	char *last = NULL;
	struct dkimf_unbound *ub;

	assert(srv != NULL);
	assert(nslist != NULL);

	ub = srv;

	cp = strdup(nslist);
	if (cp == NULL)
		return DKIM_DNS_ERROR;

	for (p = strtok_r(cp, ",", &last);
	     p != NULL;
	     p = strtok_r(NULL, ",", &last))
	{
		if (ub_ctx_set_fwd(ub->ub_ub, p) != 0)
		{
			free(cp);
			return DKIM_DNS_ERROR;
		}
	}

	free(cp);
	return DKIM_DNS_SUCCESS;
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
dkimf_rbl_unbound_setup(RBL *rbl)
{
	assert(rbl != NULL);

	(void) rbl_dns_set_query_start(rbl, dkimf_ub_query);
	(void) rbl_dns_set_query_cancel(rbl, dkimf_ub_cancel);
	(void) rbl_dns_set_query_waitreply(rbl, dkimf_ub_waitreply);
	(void) rbl_dns_set_init(rbl, dkimf_ub_init);
	(void) rbl_dns_set_close(rbl, dkimf_ub_close);
	(void) rbl_dns_set_nslist(rbl, dkimf_ub_nslist);
	(void) rbl_dns_set_config(rbl, dkimf_ub_config);
	(void) rbl_dns_set_trustanchor(rbl, dkimf_ub_trustanchor);

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
dkimf_unbound_setup(DKIM_LIB *lib)
{
	assert(lib != NULL);

	(void) dkim_dns_set_query_start(lib, dkimf_ub_query);
	(void) dkim_dns_set_query_cancel(lib, dkimf_ub_cancel);
	(void) dkim_dns_set_query_waitreply(lib, dkimf_ub_waitreply);
	(void) dkim_dns_set_init(lib, dkimf_ub_init);
	(void) dkim_dns_set_close(lib, dkimf_ub_close);
	(void) dkim_dns_set_nslist(lib, dkimf_ub_nslist);
	(void) dkim_dns_set_config(lib, dkimf_ub_config);
	(void) dkim_dns_set_trustanchor(lib, dkimf_ub_trustanchor);

	return 0;
}
#endif /* USE_UNBOUND */

/*
**  DKIMF_FILEDNS_QUERY -- function passed to libopendkim to handle new
**                         requests
**
**  Parameters:
**  	srv -- service handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_filedns_query(void *srv, int type, unsigned char *query,
                    unsigned char *buf, size_t buflen, void **qh)
{
	struct dkimf_fquery *fq;
	size_t qlen;

	assert(srv != NULL);
	assert(query != NULL);
	assert(buf != NULL);
	assert(qh != NULL);

	if (type != T_TXT)
		return DKIM_DNS_SUCCESS;

	fq = malloc(sizeof *fq);
	if (fq == NULL)
		return DKIM_DNS_ERROR;
	fq->fq_rbuf = buf;
	fq->fq_rbuflen = buflen;

	qlen = res_mkquery(QUERY, query, C_IN, type, NULL, 0, NULL,
	                   fq->fq_qbuf, sizeof fq->fq_qbuf);
	if (qlen == (size_t) -1)
	{
		free(fq);
		return DKIM_DNS_ERROR;
	}

	fq->fq_qlen = qlen;

	*qh = fq;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_FILEDNS_CANCEL -- function passed to libopendkim to handle cancel
**                          requests
**
**  Parameters:
**  	srv -- service handle
**  	q -- query handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

static int
dkimf_filedns_cancel(void *srv, void *q)
{
	struct dkimf_fquery *fq;

	assert(srv != NULL);
	assert(q != NULL);

	fq = q;

	free(fq);

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_FILEDNS_WAITREPLY -- function passed to libopendkim to handle
**                             wait requests
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
dkimf_filedns_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                        int *error, int *dnssec)
{
	_Bool exists = FALSE;
	int n;
	int status;
	int qdcount;
	char *cp;
	char *eom;
	char *qstart;
	struct dkimf_fquery *fq;
	char qname[BUFRSZ + 1];
	char buf[BUFRSZ + 1];
	HEADER hdr;
	struct dkimf_db_data dbd;

	assert(srv != NULL);
	assert(qh != NULL);

	fq = (struct dkimf_fquery *) qh;

	/* recover the query */
	qstart = fq->fq_rbuf;
	cp = fq->fq_qbuf;
	eom = cp + sizeof fq->fq_qbuf;
	memcpy(&hdr, cp, sizeof hdr);
	cp += HFIXEDSZ;

	/* skip over the name at the front of the answer */
	memset(qname, '\0', sizeof qname);
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		(void) dn_expand((unsigned char *) fq->fq_qbuf, eom, cp,
		                 (char *) qname, sizeof qname);
 
		if ((n = dn_skipname(cp, eom)) < 0)
			return DKIM_DNS_ERROR;;

		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
			return DKIM_DNS_ERROR;
;
		cp += (INT16SZ + INT16SZ);
	}

	/* search the DB */
	dbd.dbdata_buffer = buf;
	dbd.dbdata_buflen = sizeof buf;
	dbd.dbdata_flags = 0;

	memset(buf, '\0', sizeof buf);

	/* see if it's in the DB */
	status = dkimf_db_get((DKIMF_DB) srv, qname, strlen(qname), &dbd, 1,
	                      &exists);
	if (status != 0)
		return DKIM_DNS_ERROR;

	/* prepare a reply header */
	hdr.qr = 1;

	if (!exists)
	{			/* not found; set up an NXDOMAIN reply */
		hdr.rcode = NXDOMAIN;
		hdr.ancount = htons(0);

		memcpy(fq->fq_qbuf, &hdr, sizeof hdr);

		*bytes = fq->fq_qlen;
	}
	else
	{			/* found, construct the reply */
		int elen;
		int slen;
		int olen;
		char *q;
		unsigned char *len;
		unsigned char *dnptrs[3];
		unsigned char **lastdnptr;
		HEADER newhdr;

		lastdnptr = &dnptrs[2];

		memset(&newhdr, '\0', sizeof newhdr);
		memset(&dnptrs, '\0', sizeof dnptrs);
		
		newhdr.qdcount = htons(1);
		newhdr.ancount = htons(1);
		newhdr.rcode = NOERROR;
		newhdr.opcode = hdr.opcode;
		newhdr.qr = 1;
		newhdr.id = hdr.id;

		dnptrs[0] = fq->fq_qbuf;

		/* copy out the new header */
		memcpy(fq->fq_rbuf, &newhdr, sizeof newhdr);

		cp = fq->fq_rbuf + HFIXEDSZ;
		eom = fq->fq_rbuf + fq->fq_rbuflen;

		/* question section */
		elen = dn_comp(qname, cp, eom - cp, dnptrs, lastdnptr);
		if (elen == -1)
			return DKIM_DNS_ERROR;
		cp += elen;
		PUTSHORT(T_TXT, cp);
		PUTSHORT(C_IN, cp);

		/* answer section */
		elen = dn_comp(qname, cp, eom - cp, dnptrs, lastdnptr);
		if (elen == -1)
			return DKIM_DNS_ERROR;
		cp += elen;
		PUTSHORT(T_TXT, cp);
		PUTSHORT(C_IN, cp);
		PUTLONG(0L, cp);

		len = cp;
		cp += INT16SZ;

		slen = dbd.dbdata_buflen;
		olen = 0;
		q = buf;

		while (slen > 0)
		{
			elen = MIN(slen, 255);
			*cp = (char) elen;
			cp++;
			olen++;
			memcpy(cp, q, elen);
			q += elen;
			cp += elen;
			olen += elen;
			slen -= elen;
		}

		eom = cp;

		cp = len;
		PUTSHORT(olen, cp);

		*bytes = eom - qstart;
	}

	if (dnssec != NULL)
		*dnssec = DKIM_DNSSEC_UNKNOWN;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIMF_FILEDNS_SETUP -- connect a file DNS to libopendkim
**
**  Parameters:
**  	lib -- libopendkim handle
**  	db -- data set from which to read
**
**  Return value:
**  	0 on success, -1 on failure
*/

int
dkimf_filedns_setup(DKIM_LIB *lib, DKIMF_DB db)
{
	assert(lib != NULL);
	assert(db != NULL);

	(void) dkim_dns_set_query_service(lib, db);
	(void) dkim_dns_set_query_start(lib, dkimf_filedns_query);
	(void) dkim_dns_set_query_cancel(lib, dkimf_filedns_cancel);
	(void) dkim_dns_set_query_waitreply(lib, dkimf_filedns_waitreply);
	(void) dkim_dns_set_init(lib, NULL);
	(void) dkim_dns_set_close(lib, NULL);
	(void) dkim_dns_set_nslist(lib, NULL);
	(void) dkim_dns_set_config(lib, NULL);
	(void) dkim_dns_set_trustanchor(lib, NULL);

	return 0;
}

#ifdef _FFR_VBR
# ifdef USE_UNBOUND
/*
**  DKIMF_VBR_UNBOUND_SETUP -- connect libunbound to libvbr
**
**  Parameters:
**  	vbr -- libvbr handle
**  	ub -- dkimf_unbound handle to use
**
**  Return value:
**  	0 on success, -1 on failure
*/

int
dkimf_vbr_unbound_setup(VBR *vbr)
{
	assert(vbr != NULL);

	(void) vbr_dns_set_query_start(vbr, dkimf_ub_query);
	(void) vbr_dns_set_query_cancel(vbr, dkimf_ub_cancel);
	(void) vbr_dns_set_query_waitreply(vbr, dkimf_ub_waitreply);
	(void) vbr_dns_set_init(vbr, dkimf_ub_init);
	(void) vbr_dns_set_close(vbr, dkimf_ub_close);
	(void) vbr_dns_set_nslist(vbr, dkimf_ub_nslist);
	(void) vbr_dns_set_config(vbr, dkimf_ub_config);
	(void) vbr_dns_set_trustanchor(vbr, dkimf_ub_trustanchor);

	return 0;
}
# endif /* USE_UNBOUND */
#endif /* _FFR_VBR */
