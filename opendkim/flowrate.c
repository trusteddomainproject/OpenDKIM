/*
**  Copyright (c) 2011-2013, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

#ifdef _FFR_RATE_LIMIT

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendkim includes */
#include "flowrate.h"
#include "opendkim.h"
#include "opendkim-db.h"

/* DATA TYPES */
struct flowdata
{
	time_t		fd_since;
	unsigned int	fd_limit;
	unsigned int	fd_count;
};

/* GLOBALS */
pthread_mutex_t ratelock;

/*
**  DKIMF_RATE_CHECK -- conduct a rate limit check, expire data, increment
**
**  Parameters:
**  	domain -- domain name being queried (or NULL for unsigned mail)
**  	ratedb -- data set containing per-domain rate limits
**  	flowdb -- data set containing per-domain flow data (updated)
**  	factor -- divisor
**  	ttl -- TTL to apply (i.e. data expiration)
**  	limit -- limit for this domain (returned)
**
**  Return value:
**  	-1 -- error
**  	0 -- success
**  	1 -- success, and the domain is at or past its limit
*/

int
dkimf_rate_check(const char *domain, DKIMF_DB ratedb, DKIMF_DB flowdb,
                 int factor, int ttl, unsigned int *limit)
{
	_Bool found = FALSE;
	int status;
	time_t now;
	struct dkimf_db_data dbd;
	struct flowdata f;
	char limbuf[BUFRSZ];

	assert(ratedb != NULL);
	assert(flowdb != NULL);

	if (domain == NULL)
		domain = ".";

	memset(&f, '\0', sizeof f);

	pthread_mutex_lock(&ratelock);

	/* get the current flow data, if any */
	dbd.dbdata_buffer = (void *) &f;
	dbd.dbdata_buflen = sizeof f;
	dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;
	status = dkimf_db_get(flowdb, (void *) domain, 0, &dbd, 1, &found);
	if (status != 0)
	{
		pthread_mutex_unlock(&ratelock);
		return -1;
	}

	(void) time(&now);

	/* if none or if it expired, retrieve the limit */
	if (!found || f.fd_since + ttl <= now)
	{
		char *p;

		dbd.dbdata_buffer = limbuf;
		dbd.dbdata_buflen = sizeof limbuf;
		dbd.dbdata_flags = 0;
		status = dkimf_db_get(ratedb, (void *) domain, 0, &dbd, 1,
		                      &found);
		if (status != 0)
		{
			pthread_mutex_unlock(&ratelock);
			return -1;
		}
		else if (!found)
		{
			pthread_mutex_unlock(&ratelock);
			return 0;
		}

		f.fd_count = 0;
		f.fd_limit = (unsigned int) strtoul(limbuf, &p, 10) / factor;
		(void) time(&f.fd_since);
		if (*p != '\0')
		{
			pthread_mutex_unlock(&ratelock);
			return -1;
		}
	}

	/* increment the count */
	f.fd_count++;

	/* write it back out */
	status = dkimf_db_put(flowdb, (void *) domain, strlen(domain),
	                      &f, sizeof f);
	if (status != 0)
	{
		pthread_mutex_unlock(&ratelock);
		return -1;
	}

	pthread_mutex_unlock(&ratelock);

	/* copy the limit out */
	if (limit != NULL)
		*limit = f.fd_limit;

	return (f.fd_count >= f.fd_limit ? 1 : 0);
}

#endif /* _FFR_RATE_LIMIT */
