/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2011-2013, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

#ifdef _FFR_REPUTATION

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>

/* libopendkim includes */
#include <dkim.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendkim includes */
#include "reputation.h"
#include "opendkim.h"
#include "opendkim-db.h"

/* macros */
#define DKIMF_REP_DEFCACHE	"db:"
#define	DKIMF_REP_MAXHASHES	64
#define	DKIMF_REP_NULLDOMAIN	"UNSIGNED"
#define	DKIMF_REP_LOWTIME	"LOW-TIME"

/* data types */
struct reputation
{
	time_t		rep_ttl;
	time_t		rep_lastflush;
	unsigned int	rep_factor;
	unsigned int	rep_minimum;
	DKIMF_DB	rep_reps;
	DKIMF_DB	rep_dups;
	DKIMF_DB	rep_limits;
	DKIMF_DB	rep_limitmods;
	DKIMF_DB	rep_ratios;
	DKIMF_DB	rep_counts;
	DKIMF_DB	rep_spam;
	DKIMF_DB	rep_lowtime;
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
**  	cachettl -- TTL for cache entries
**  	cache -- data set to which to cache
**  	dups -- data set to which to record duplicates
**  	limits -- DB from which to get per-domain limits
**  	limitmods -- DB from which to get per-domain limit modifiers
**  	ratios -- DB from which to get per-domain ratios
**  	lowtime -- DB from which to check for low-time domain status
**
**  Return value:
**  	0 on success, -1 on error.
*/

int
dkimf_rep_init(DKIMF_REP *rep, time_t factor, unsigned int minimum,
               unsigned int cachettl, char *cache, char *dups, DKIMF_DB limits,
               DKIMF_DB limitmods, DKIMF_DB ratios, DKIMF_DB lowtime)
{
	int status;
	DKIMF_REP new;

	assert(rep != NULL);
	assert(ratios != NULL);
	assert(factor != 0);

	new = malloc(sizeof *new);
	if (new == NULL)
		return -1;

#ifdef USE_MDB
	if (cache == NULL || dups == NULL)
		return -1;
#else /* USE_MDB */
	if (cache == NULL)
		cache = DKIMF_REP_DEFCACHE;
	if (dups == NULL)
		dups = DKIMF_REP_DEFCACHE;
#endif /* USE_MDB */

	new->rep_lastflush = time(NULL);
	new->rep_ttl = cachettl;
	new->rep_factor = factor;
	new->rep_limits = limits;
	new->rep_limitmods = limitmods;
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

	status = dkimf_db_open(&new->rep_dups, dups, 0, NULL, NULL);
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
**  	rep -- reputation service handle
**  	sig -- a valid signature on this message
**  	spam -- spammy or not spammy?  That is the question.
**  	hash -- hash of the message, for counting dups
**  	hashlen -- number of bytes in the hash
**  	limit -- limit for this signer (returned)
**  	ratio -- spam ratio for this signer (returned)
**  	count -- message count for this signer (returned)
**  	spamcnt -- spam count for this signer (returned)
**  	errbuf -- buffer to receive errors
**  	errlen -- bytes available at errbuf
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
                float *ratio, unsigned long *count, unsigned long *spamcnt,
                char *errbuf, size_t errlen)
{
	_Bool f;
	size_t dlen;
	size_t hlen;
	time_t when;
	time_t now;
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
		strlcpy(domain, DKIMF_REP_NULLDOMAIN, sizeof domain);
	else
		strlcpy(domain, dkim_sig_getdomain(sig), sizeof domain);

	dlen = strlen(domain);

	/* check cache first */
	f = FALSE;
	if (dkimf_db_get(rep->rep_reps, domain, dlen, req, 1, &f) != 0)
	{
		if (errbuf != NULL)
			dkimf_db_strerror(rep->rep_reps, errbuf, errlen);
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
				if (errbuf != NULL)
				{
					dkimf_db_strerror(rep->rep_reps,
					                  errbuf, errlen);
				}
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
			strlcpy(domain, DKIMF_REP_LOWTIME, sizeof domain);
			dlen = strlen(domain);
		}
		
		f = FALSE;

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
				if (errbuf != NULL)
				{
					dkimf_db_strerror(rep->rep_reps,
					                  errbuf, errlen);
				}
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
					if (errbuf != NULL)
					{
						dkimf_db_strerror(rep->rep_reps,
						                  errbuf,
						                  errlen);
					}
					pthread_mutex_unlock(&rep->rep_lock);
					return -1;
				}
			}

			if (!f)
			{
				if (dkimf_db_get(rep->rep_limits, "*", 1, req,
				                 fields, &f) != 0)
				{
					if (errbuf != NULL)
					{
						dkimf_db_strerror(rep->rep_reps,
						                  errbuf,
						                  errlen);
					}
					pthread_mutex_unlock(&rep->rep_lock);
					return -1;
				}
			}

			if (!f || req[fields - 1].dbdata_buflen >= sizeof buf)
			{
				pthread_mutex_unlock(&rep->rep_lock);
				return 2;
			}

			buf[req[fields - 1].dbdata_buflen] = '\0';

			reps.reps_limit = (unsigned long) (ceil((double) strtoul(buf, &p, 10) / (double) rep->rep_factor) + 1.);
			if (p != NULL && *p != '\0')
			{
				if (errbuf != NULL)
				{
					snprintf(errbuf, errlen,
					         "failed to parse limit reply");
				}
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}

			if (rep->rep_limitmods != NULL)
			{
				f = FALSE;

				req[0].dbdata_buffer = buf;
				req[0].dbdata_buflen = sizeof buf;
				req[0].dbdata_flags = 0;

				if (dkimf_db_get(rep->rep_limitmods,
				                 domain, dlen,
				                 req, 1, &f) != 0)
				{
					if (errbuf != NULL)
					{
						dkimf_db_strerror(rep->rep_reps,
						                  errbuf,
						                  errlen);
					}
					pthread_mutex_unlock(&rep->rep_lock);
					return -1;
				}

				if (f && req[0].dbdata_buflen < sizeof buf)
				{
					unsigned int mod = 0;

					buf[req[0].dbdata_buflen] = '\0';
					mod = strtoul(&buf[1], &p, 10);
					if (*p != '\0')
						buf[0] = '\0';

					switch (buf[0])
					{
					  case '+':
						reps.reps_limit += mod;
						break;

					  case '*':
						reps.reps_limit *= mod;
						break;

					  case '-':
						reps.reps_limit -= mod;
						break;

					  case '/':
						if (mod != 0)
							reps.reps_limit /= mod;
						break;

					  case '=':
						reps.reps_limit = mod;
						break;
					}
				}
			}
		}

		/* get the spam ratio */
		req[0].dbdata_buffer = buf;
		req[0].dbdata_buflen = sizeof buf;
		req[0].dbdata_flags = 0;

		f = FALSE;

		if (dkimf_db_get(rep->rep_ratios, domain, dlen, req,
		                 1, &f) != 0)
		{
			if (errbuf != NULL)
			{
				dkimf_db_strerror(rep->rep_reps,
				                  errbuf, errlen);
			}
			pthread_mutex_unlock(&rep->rep_lock);
			return -1;
		}

		if (!f && !lowtime && sig != NULL)
		{
			if (dkimf_db_get(rep->rep_ratios,
			                 DKIMF_REP_LOWTIME,
			                 strlen(DKIMF_REP_LOWTIME),
			                 req, 1, &f) != 0)
			{
				if (errbuf != NULL)
				{
					dkimf_db_strerror(rep->rep_reps,
					                  errbuf, errlen);
				}
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}
		}

		if (!f)
		{
			if (dkimf_db_get(rep->rep_ratios, "*", 1, req,
			                 1, &f) != 0)
			{
				if (errbuf != NULL)
				{
					dkimf_db_strerror(rep->rep_reps,
					                  errbuf, errlen);
				}
				pthread_mutex_unlock(&rep->rep_lock);
				return -1;
			}
		}

		if (!f || req[0].dbdata_buflen >= sizeof buf)
		{
			pthread_mutex_unlock(&rep->rep_lock);
			return 2;
		}

		buf[req[0].dbdata_buflen] = '\0';
		p = NULL;
		reps.reps_ratio = strtof(buf, &p);
		if (p != NULL && *p != '\0')
		{
			if (errbuf != NULL)
			{
				snprintf(errbuf, errlen,
				         "failed to parse ratio reply");
			}
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
		if (errbuf != NULL)
			dkimf_db_strerror(rep->rep_reps, errbuf, errlen);
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
			dkimf_db_strerror(rep->rep_reps, errbuf, errlen);
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

/*
**  DKIMF_REP_CHOWN_CACHE -- set the owner of a cache file
**
**  Parameters:
**  	rep -- reputation handle
**  	uid -- target UID
**
**  Return value:
**  	0 -- success
**  	-1 -- failure
*/

int
dkimf_rep_chown_cache(DKIMF_REP rep, uid_t uid)
{
	assert(rep != NULL);
	assert(uid >= 0);

	if (dkimf_db_chown(rep->rep_reps, uid) == 1)
		return 0;
	else
		return -1;
}
#endif /* _FFR_REPUTATION */
