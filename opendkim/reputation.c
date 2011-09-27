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
#include <assert.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "reputation.h"
#include "opendkim.h"
#include "opendkim-db.h"

/* macros */
#define	DKIMF_REP_DEFTTL	3600
#define	DKIMF_REP_LOWTIMEDOMAIN	"LOW-TIME"
#define	DKIMF_REP_MAXHASHES	64
#define	DKIMF_REP_NULLDOMAIN	"NULL"

/* data types */
struct reputation
{
	DKIMF_DB	rep_reps;
	DKIMF_DB	rep_dups;
	DKIMF_DB	rep_limits;
	DKIMF_DB	rep_ratios;
	DKIMF_DB	rep_counts;
	DKIMF_DB	rep_spam;
	time_t		rep_ttl;
	time_t		rep_lastflush;
	unsigned int	rep_factor;
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
**  	rephandle -- reputation DB query handle (returned)
**
**  Return value:
**  	0 on success, -1 on error.
*/

int
dkimf_rep_init(DKIMF_REP *rep, time_t factor,
               DKIMF_DB limits, DKIMF_DB ratios)
{
	int status;
	DKIMF_REP new;

	assert(rep != NULL);
	assert(limits != NULL);
	assert(ratios != NULL);
	assert(factor != 0);

	new = malloc(sizeof *new);
	if (new == NULL)
		return -1;

	new->rep_lastflush = time(NULL);
	new->rep_ttl = DKIMF_REP_DEFTTL;
	new->rep_factor = factor;
	new->rep_limits = limits;
	new->rep_ratios = ratios;

	if (pthread_mutex_init(&new->rep_lock, NULL) != 0)
	{
		free(new);
		return -1;
	}

	status = dkimf_db_open(&new->rep_reps, "db:", 0, NULL, NULL);
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
dkimf_rep_check(DKIMF_REP rep, DKIM_SIGINFO *sig, _Bool lowtime, _Bool spam,
                void *hash, size_t hashlen)
{
	_Bool f;
	size_t dlen;
	size_t hlen;
	time_t when;
	time_t now;
	void *hh;
	void *bh;
	struct dkimf_db_data req;
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
		
		req.dbdata_buffer = (void *) &when;
		req.dbdata_buflen = sizeof when;
		req.dbdata_flags = DKIMF_DB_DATA_BINARY;

		while (dkimf_db_walk(rep->rep_dups, f, hashbuf, &hlen,
		                     &req, 1) == 0)
		{
			if (when + rep->rep_ttl < now)
			{
				(void) dkimf_db_delete(rep->rep_reps, hashbuf,
				                       hlen);
			}

			req.dbdata_buffer = (void *) &when;
			req.dbdata_buflen = sizeof when;
			req.dbdata_flags = DKIMF_DB_DATA_BINARY;

			f = FALSE;
		}

		req.dbdata_buffer = (void *) &reps;
		req.dbdata_buflen = sizeof reps;
		req.dbdata_flags = DKIMF_DB_DATA_BINARY;

		f = TRUE;
		while (dkimf_db_walk(rep->rep_reps, f, hashbuf, &hlen,
		                     &req, 1) == 0)
		{
			if (reps.reps_retrieved + rep->rep_ttl < now)
			{
				(void) dkimf_db_delete(rep->rep_reps, hashbuf,
				                       hlen);
			}

			req.dbdata_buffer = (void *) &reps;
			req.dbdata_buflen = sizeof reps;
			req.dbdata_flags = DKIMF_DB_DATA_BINARY;

			f = FALSE;
		}

		rep->rep_lastflush = now;
	}

	/* get the ratio and limit for this domain */
	req.dbdata_buffer = (void *) &reps;
	req.dbdata_buflen = sizeof reps;
	req.dbdata_flags = DKIMF_DB_DATA_BINARY;

	if (lowtime)
		dkim_strlcpy(domain, DKIMF_REP_LOWTIMEDOMAIN, sizeof domain);
	else if (sig == NULL)
		dkim_strlcpy(domain, DKIMF_REP_NULLDOMAIN, sizeof domain);
	else
		dkim_strlcpy(domain, dkim_sig_getdomain(sig), sizeof domain);

	dlen = strlen(domain);

	/* check cache first */
	f = FALSE;
	if (dkimf_db_get(rep->rep_reps, domain, dlen, &req, 1, &f) != 0)
	{
		pthread_mutex_unlock(&rep->rep_lock);
		return -1;
	}

	if (!f)
	{
		char *p;

		/* cache miss; build a new cache entry */
		reps.reps_count = 0;
		reps.reps_spam = 0;
		reps.reps_retrieved = time(NULL);

		req.dbdata_buffer = buf;
		req.dbdata_buflen = sizeof buf;
		req.dbdata_flags = 0;

		/* get the total message limit */
		if (dkimf_db_get(rep->rep_limits, domain, dlen, &req,
		                 1, &f) != 0)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}

		if (!f)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return 2;
		}

		reps.reps_limit = strtoul(buf, &p, 10) / rep->rep_factor + 1;
		if (*p != '\0')
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}

		/* get the spam ratio */
		req.dbdata_buffer = buf;
		req.dbdata_buflen = sizeof buf;
		req.dbdata_flags = 0;

		if (dkimf_db_get(rep->rep_ratios, domain, dlen, &req,
		                 1, &f) != 0)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}

		if (!f)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return 2;
		}

		reps.reps_ratio = strtof(buf, &p);
		if (*p != '\0')
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}
	}

	req.dbdata_buffer = (void *) &when;
	req.dbdata_buflen = sizeof when;
	req.dbdata_flags = DKIMF_DB_DATA_BINARY;

	f = FALSE;

	if (dkimf_db_get(rep->rep_dups, hash, hashlen, &req, 1, &f) != 0)
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

	/* if accepting it now would be within limits */
	if (reps.reps_count < reps.reps_limit &&
	    reps.reps_spam / reps.reps_count < reps.reps_ratio)
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
