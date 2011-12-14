/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
**
**  $Id: reputation.c,v 1.27.2.1 2010/10/27 21:43:09 cm-msk Exp $
*/

#ifndef lint
static char reputation_c_id[] = "@(#)$Id: stats.c,v 1.27.2.1 2010/10/27 21:43:09 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

#ifdef _FFR_REPUTATION

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "reputation.h"
#include "opendkim.h"
#include "opendkim-db.h"

/* macros */
#define	DKIMF_REP_DEFCACHE	"db:"
#define	DKIMF_REP_DEFTTL	3600
#define	DKIMF_REP_MAXHASHES	64
#define	DKIMF_REP_NULLDOMAIN	"UNSIGNED"
#define	DKIMF_REP_LOWTIME	"LOW-TIME"

/* data types */
struct reputation
{
	DKIMF_DB	rep_reps;
	DKIMF_DB	rep_dups;
	DKIMF_DB	rep_limits;
	DKIMF_DB	rep_ratios;
	DKIMF_DB	rep_counts;
	DKIMF_DB	rep_spam;
	DKIMF_DB	rep_lowtime;
	time_t		rep_ttl;
	time_t		rep_lastflush;
	unsigned int	rep_factor;
	unsigned int	rep_minimum;
	pthread_mutex_t	rep_lock;
};

struct reps
{
	time_t		reps_retrieved;
	unsigned long	reps_count;
	unsigned long	reps_limit;
	unsigned long	reps_spam;
	float		reps_ratio;
};

/*
**  DKIMF_REP_INIT -- initialize reputation
**
**  Parameters:
**  	rep -- reputation DB query handle (returned)
**  	factor -- number of slices in a reputation limit
**  	minimum -- always accept at least this many messages
**  	cache -- data set to which to cache
**  	limits -- DB from which to get per-domain limits
**  	ratios -- DB from which to get per-domain ratios
**  	lowtime -- DB from which to check for low-time domain status
**
**  Return value:
**  	0 on success, -1 on error.
*/

int
dkimf_rep_init(DKIMF_REP *rep, time_t factor, unsigned int minimum,
               char *cache, DKIMF_DB limits, DKIMF_DB ratios, DKIMF_DB lowtime)
{
	int status;
	DKIMF_REP new;

	assert(rep != NULL);
	assert(ratios != NULL);
	assert(factor != 0);

	new = malloc(sizeof *new);
	if (new == NULL)
		return -1;

	if (cache == NULL)
		cache = DKIMF_REP_DEFCACHE;

	new->rep_lastflush = time(NULL);
	new->rep_ttl = DKIMF_REP_DEFTTL;
	new->rep_factor = factor;
	new->rep_limits = limits;
	new->rep_ratios = ratios;
	new->rep_lowtime = lowtime;
	new->rep_minimum = minimum;

	if (pthread_mutex_init(&new->rep_lock, NULL) != 0)
	{
		free(new);
		return -1;
	}

	status = dkimf_db_open(&new->rep_reps, cache, 0, NULL, NULL);
	if (status != 0)
	{
		free(new);
		return -1;
	}

	status = dkimf_db_open(&new->rep_dups, "db:", 0, NULL, NULL);
	if (status != 0)
	{
		dkimf_db_close(new->rep_reps);
		free(new);
		return -1;
	}

	*rep = new;

	return 0;
}

/*
**  DKIMF_REP_CLOSE -- shut down reputation
**
**  Parameters:
**  	rephandle -- reputation DB query handle
**
**  Return value:
**  	None.
*/

void
dkimf_rep_close(DKIMF_REP rephandle)
{
	assert(rephandle != NULL);

	(void) dkimf_db_close(rephandle->rep_reps);
	(void) dkimf_db_close(rephandle->rep_dups);

	(void) pthread_mutex_destroy(&rephandle->rep_lock);
}

/*
**  DKIMF_REP_CHECK -- check reputation
**
**  Parameters:
**  	rephandle -- reputation service handle
**  	sig -- a valid signature on this message
**  	lowtime -- check low-time domain record (ignoring sig)
**  	spam -- spammy or not spammy?  That is the question.
**
**  Return value:
**  	2 -- no data found for this domain
**  	1 -- deny the request
**  	0 -- allow the request
**  	-1 -- error
**
**  Notes:
**  	If "sig" is NULL, the null domain record is queried.
*/

int
dkimf_rep_check(DKIMF_REP rep, DKIM_SIGINFO *sig, _Bool spam,
                void *hash, size_t hashlen, unsigned long *limit,
                float *ratio, unsigned long *count, unsigned long *spamcnt)
{
	_Bool f;
	size_t dlen;
	size_t hlen;
	time_t when;
	time_t now;
	void *hh;
	void *bh;
	struct dkimf_db_data req[5];
	struct reps reps;
	char buf[BUFRSZ + 1];
	char domain[DKIM_MAXHOSTNAMELEN + 1];
	unsigned char hashbuf[DKIMF_REP_MAXHASHES];

	assert(rep != NULL);

	(void) time(&now);

	pthread_mutex_lock(&rep->rep_lock);

	/* flush the caches if needed */
	if (rep->rep_lastflush + rep->rep_ttl < now)
	{
		f = TRUE;
		
		req[0].dbdata_buffer = (void *) &when;
		req[0].dbdata_buflen = sizeof when;
		req[0].dbdata_flags = DKIMF_DB_DATA_BINARY;

		hlen = sizeof hashbuf;
		while (dkimf_db_walk(rep->rep_dups, f, hashbuf, &hlen,
		                     req, 1) == 0)
		{
			if (when + rep->rep_ttl < now)
			{
				(void) dkimf_db_delete(rep->rep_dups, hashbuf,
				                       hlen);
			}

			req[0].dbdata_buffer = (void *) &when;
			req[0].dbdata_buflen = sizeof when;
			req[0].dbdata_flags = DKIMF_DB_DATA_BINARY;

			f = FALSE;
			hlen = sizeof hashbuf;
		}

		req[0].dbdata_buffer = (void *) &reps;
		req[0].dbdata_buflen = sizeof reps;
		req[0].dbdata_flags = DKIMF_DB_DATA_BINARY;

		f = TRUE;
		hlen = sizeof domain;
		memset(domain, '\0', sizeof domain);
		while (dkimf_db_walk(rep->rep_reps, f, domain, &hlen,
		                     req, 1) == 0)
		{
			if (reps.reps_retrieved + rep->rep_ttl < now)
			{
				(void) dkimf_db_delete(rep->rep_reps, domain,
				                       hlen);
			}

			req[0].dbdata_buffer = (void *) &reps;
			req[0].dbdata_buflen = sizeof reps;
			req[0].dbdata_flags = DKIMF_DB_DATA_BINARY;

			f = FALSE;
			hlen = sizeof domain;
			memset(domain, '\0', sizeof domain);
		}

		rep->rep_lastflush = now;
	}

	/* get the ratio and limit for this domain */
	req[0].dbdata_buffer = (void *) &reps;
	req[0].dbdata_buflen = sizeof reps;
	req[0].dbdata_flags = DKIMF_DB_DATA_BINARY;

	if (sig == NULL)
		dkim_strlcpy(domain, DKIMF_REP_NULLDOMAIN, sizeof domain);
	else
		dkim_strlcpy(domain, dkim_sig_getdomain(sig), sizeof domain);

	dlen = strlen(domain);

	/* check cache first */
	f = FALSE;
	if (dkimf_db_get(rep->rep_reps, domain, dlen, req, 1, &f) != 0)
	{
		pthread_mutex_unlock(&rep->rep_lock);
		return -1;
	}

	if (!f)
	{
		_Bool lowtime = FALSE;
		char *p = NULL;

		/* cache miss; build a new cache entry */
		reps.reps_count = 0;
		reps.reps_limit = ULONG_MAX;
		reps.reps_spam = 0;
		reps.reps_retrieved = time(NULL);

		req[0].dbdata_buffer = buf;
		req[0].dbdata_buflen = sizeof buf;
		req[0].dbdata_flags = 0;

		if (rep->rep_lowtime != NULL)
		{
			/* see if it's a low-time domain */
			if (dkimf_db_get(rep->rep_lowtime, domain, dlen, req,
			                 1, &f) != 0)
			{
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}

			if (f)
				lowtime = (atoi(buf) != 0);

			memset(buf, '\0', sizeof buf);

			req[0].dbdata_buffer = buf;
			req[0].dbdata_buflen = sizeof buf;
			req[0].dbdata_flags = 0;
		}

		if (lowtime)
		{
			dkim_strlcpy(domain, DKIMF_REP_LOWTIME, sizeof domain);
			dlen = strlen(domain);
		}
		
		/* get the total message limit */
		if (rep->rep_limits != NULL)
		{
			int fields = 1;

			if (dkimf_db_type(rep->rep_limits) == DKIMF_DB_TYPE_REPUTE)
				fields = 5;

			memset(req, '\0', sizeof req);

			req[fields - 1].dbdata_buffer = buf;
			req[fields - 1].dbdata_buflen = sizeof buf;
			req[fields - 1].dbdata_flags = 0;

			if (dkimf_db_get(rep->rep_limits, domain, dlen, req,
			                 fields, &f) != 0)
			{
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}

			if (!f && !lowtime && sig != NULL)
			{
				if (dkimf_db_get(rep->rep_limits,
				                 DKIMF_REP_LOWTIME,
				                 strlen(DKIMF_REP_LOWTIME),
				                 req, fields, &f) != 0)
				{
					pthread_mutex_unlock(&rep->rep_lock);
					return -1;
				}
			}

			if (!f)
			{
				if (dkimf_db_get(rep->rep_limits, "*", 1, req,
				                 fields, &f) != 0)
				{
					pthread_mutex_unlock(&rep->rep_lock);
					return -1;
				}
			}

			if (!f)
			{
				pthread_mutex_unlock(&rep->rep_lock);
				return 2;
			}

			reps.reps_limit = (unsigned long) (ceil((double) strtoul(buf, &p, 10) / (double) rep->rep_factor) + 1.);
			if (p != NULL && *p != '\0')
			{
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}
		}

		/* get the spam ratio */
		req[0].dbdata_buffer = buf;
		req[0].dbdata_buflen = sizeof buf;
		req[0].dbdata_flags = 0;

		if (dkimf_db_get(rep->rep_ratios, domain, dlen, req,
		                 1, &f) != 0)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}

		if (!f && !lowtime && sig != NULL)
		{
			if (dkimf_db_get(rep->rep_limits,
			                 DKIMF_REP_LOWTIME,
			                 strlen(DKIMF_REP_LOWTIME),
			                 req, 1, &f) != 0)
			{
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}
		}

		if (!f)
		{
			if (dkimf_db_get(rep->rep_ratios, "*", 1, req,
			                 1, &f) != 0)
			{
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}
		}

		if (!f)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return 2;
		}

		p = NULL;
		reps.reps_ratio = strtof(buf, &p);
		if (p != NULL && *p != '\0')
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}
	}

	req[0].dbdata_buffer = (void *) &when;
	req[0].dbdata_buflen = sizeof when;
	req[0].dbdata_flags = DKIMF_DB_DATA_BINARY;

	f = FALSE;

	if (dkimf_db_get(rep->rep_dups, hash, hashlen, req, 1, &f) != 0)
	{
		pthread_mutex_unlock(&rep->rep_lock);
		return -1;
	}

	/* up the counts if this is new */
	if (!f)
	{
		reps.reps_count++;
		if (spam)
			reps.reps_spam++;

		/* write it to the cache */
		if (dkimf_db_put(rep->rep_reps, domain, dlen,
		                 &reps, sizeof reps) != 0)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}
	}

	/* export requested stats */
	if (limit != NULL)
		*limit = reps.reps_limit;
	if (ratio != NULL)
		*ratio = reps.reps_ratio;
	if (count != NULL)
		*count = reps.reps_count;
	if (spamcnt != NULL)
		*spamcnt = reps.reps_spam;

	/* if accepting it now would be within limits */
	if (reps.reps_count <= rep->rep_minimum ||
	    (reps.reps_count <= reps.reps_limit &&
	     (float) reps.reps_spam / (float) reps.reps_count <= reps.reps_ratio))
	{
		/* remove from rep_dups if found there */
		(void) dkimf_db_delete(rep->rep_dups, hash, hashlen);

		pthread_mutex_unlock(&rep->rep_lock);
		return 0;
	}
	else
	{
		/* record the dup */
		(void) dkimf_db_put(rep->rep_dups, hash, hashlen,
		                    &now, sizeof now);

		pthread_mutex_unlock(&rep->rep_lock);
		return 1;
	}
}
#endif /* _FFR_REPUTATION */
