/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, 2013, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

#ifdef QUERY_CACHE

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

/* libdb includes */
#include <db.h>

/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-cache.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* limits, macros, etc. */
#define	BUFRSZ			1024
#define DB_MODE			(S_IRUSR|S_IWUSR)

#ifndef DB_NOTFOUND
# define DB_NOTFOUND		1
#endif /* ! DB_NOTFOUND */

#ifndef DB_VERSION_MAJOR
# define DB_VERSION_MAJOR	1
#endif /* ! DB_VERSION_MAJOR */

#define DB_VERSION_CHECK(x,y,z) ((DB_VERSION_MAJOR == (x) && \
				  DB_VERSION_MINOR == (y) && \
				  DB_VERSION_PATCH >= (z)) || \
				 (DB_VERSION_MAJOR == (x) && \
				  DB_VERSION_MINOR > (y)) || \
				 DB_VERSION_MAJOR > (x))

/* data types */
struct dkim_cache_entry
{
	int		cache_ttl;
	time_t		cache_when;
	char		cache_data[BUFRSZ + 1];
};

/* globals */
static pthread_mutex_t cache_stats_lock; /* stats lock */
static u_int c_hits = 0;		/* cache hits */
static u_int c_queries = 0;		/* cache queries */
static u_int c_expired = 0;		/* expired cache hits */
static pthread_mutex_t cache_lock;	/* cache lock */

/*
**  DKIM_CACHE_INIT -- initialize an on-disk cache of entries
**
**  Parameters:
**  	err -- error code (returned)
**  	tmpdir -- temporary directory to use (may be NULL)
**
**  Return value:
**  	A DB handle referring to the cache, or NULL on error.
*/

DB *
dkim_cache_init(int *err, char *tmpdir)
{
	int status = 0;
	DB *cache = NULL;

	c_hits = 0;
	c_queries = 0;
	c_expired = 0;

	(void) pthread_mutex_init(&cache_stats_lock, NULL);
	(void) pthread_mutex_init(&cache_lock, NULL);

#if DB_VERSION_CHECK(3,0,0)
	status = db_create(&cache, NULL, 0);
	if (status == 0)
	{
# if DB_VERSION_CHECK(4,2,0)
		/* tell libdb which temporary directory to use */
		if (tmpdir != NULL && tmpdir[0] != '\0')
		{
			DB_ENV *env = NULL;

#  if DB_VERSION_CHECK(4,3,0)
			env = cache->get_env(cache);
#  else /* DB_VERSION_CHECK(4,3,0) */
			(void) cache->get_env(cache, &env);
#  endif /* DB_VERISON_CHECK(4,3,0) */

			if (env != NULL)
				(void) env->set_tmp_dir(env, tmpdir);
		}
# endif /* DB_VERISON_CHECK(4,2,0) */

# if DB_VERSION_CHECK(4,1,25)
		status = cache->open(cache, NULL, NULL, NULL, DB_HASH,
		                     DB_CREATE, DB_MODE);
# else /* DB_VERSION_CHECK(4,1,25) */
		status = cache->open(cache, NULL, NULL, DB_HASH,
		                     DB_CREATE, DB_MODE);
# endif /* DB_VERSION_CHECK(4,1,25) */
	}
#elif DB_VERSION_CHECK(2,0,0)
	status = db_open(NULL, DB_HASH, DB_CREATE, DB_MODE,
	                 NULL, NULL, &cache);
#else /* ! DB_VERSION_CHECK(2,0,0) */
	cache = dbopen(NULL, (O_CREAT|O_RDWR), DB_MODE, DB_HASH, NULL);
	if (cache == NULL)
		status = errno;
#endif /* DB_VERSION_CHECK */

	if (status != 0)
	{
		if (err != NULL)
			*err = status;

		return NULL;
	}

	return cache;
}

/*
**  DKIM_CACHE_QUERY -- query an on-disk cache of entries
**
**  Parameters:
**  	db -- DB handle referring to the cache
**  	str -- key to query
**  	ttl -- time-to-live; ignore any record older than this; if 0, apply
**  	       the TTL in the record
**  	buf -- buffer into which to write any cached data found
**  	buflen -- number of bytes at "buffer" (returned); caller should set
**  	          this to the maximum space available and use the returned
**  	          value as the length of the data returned
**  	err -- error code (returned)
**
**  Return value:
**  	-1 -- error; caller should check "err"
**  	0 -- no error; record found and data returned
**  	1 -- no data found or data has expired
*/

int
dkim_cache_query(DB *db, char *str, int ttl, char *buf, size_t *buflen,
                 int *err)
{
	int status;
	time_t now;
	DBT q;
	DBT d;
	struct dkim_cache_entry ce;

	assert(db != NULL);
	assert(str != NULL);
	assert(buf != NULL);
	assert(err != NULL);

	memset(&q, '\0', sizeof q);
	memset(&d, '\0', sizeof d);

	q.data = str;
	q.size = strlen(q.data);

#if DB_VERSION_CHECK(2,0,0)
	d.flags = DB_DBT_USERMEM;
	d.data = (void *) &ce;
	d.ulen = sizeof ce;
#endif /* DB_VERSION_CHECK(2,0,0) */

	(void) time(&now);

	pthread_mutex_lock(&cache_stats_lock);
	c_queries++;
	pthread_mutex_unlock(&cache_stats_lock);

	pthread_mutex_lock(&cache_lock);

#if DB_VERSION_CHECK(2,0,0)
	status = db->get(db, NULL, &q, &d, 0);
#else /* DB_VERSION_CHECK(2,0,0) */
	status = db->get(db, &q, &d, 0);
#endif /* DB_VERSION_CHECK(2,0,0) */

	pthread_mutex_unlock(&cache_lock);

	if (status == 0)
	{
#if !DB_VERSION_CHECK(2,0,0)
		memset(&ce, '\0', sizeof ce);
		memcpy(&ce, d.data, MIN(sizeof ce, d.size));
#endif /* ! DB_VERSION_CHECK(2,0,0) */

		if (ttl != 0)
			ce.cache_ttl = ttl;
		if (ce.cache_when + ce.cache_ttl < now)
		{
			pthread_mutex_lock(&cache_stats_lock);
			c_expired++;
			pthread_mutex_unlock(&cache_stats_lock);

			return 1;
		}

		pthread_mutex_lock(&cache_stats_lock);
		c_hits++;
		pthread_mutex_unlock(&cache_stats_lock);

		strlcpy(buf, ce.cache_data, *buflen);
		*buflen = strlen(ce.cache_data);
		return 0;
	}
	else if (status != DB_NOTFOUND)
	{
		*err = status;
		return -1;
	}
	else
	{
		return 1;
	}
}

/*
**  DKIM_CACHE_INSERT -- insert data into an on-disk cache of entries
**
**  Parameters:
**  	db -- DB handle referring to the cache
**  	str -- key to insert
**  	data -- data to insert
**  	ttl -- time-to-live
**  	err -- error code (returned)
**
**  Return value:
**  	-1 -- error; caller should check "err"
**  	0 -- cache updated
*/

int
dkim_cache_insert(DB *db, char *str, char *data, int ttl, int *err)
{
	int status;
	time_t now;
	DBT q;
	DBT d;
	struct dkim_cache_entry ce;

	assert(db != NULL);
	assert(str != NULL);
	assert(data != NULL);
	assert(err != NULL);

	(void) time(&now);

	memset(&q, '\0', sizeof q);
	memset(&d, '\0', sizeof d);

	q.data = str;
	q.size = strlen(str);

	d.data = (void *) &ce;
	d.size = sizeof ce;

	ce.cache_when = now;
	ce.cache_ttl = ttl;
	strlcpy(ce.cache_data, data, sizeof ce.cache_data);

	pthread_mutex_lock(&cache_lock);

#if DB_VERSION_CHECK(2,0,0)
	status = db->put(db, NULL, &q, &d, 0);
#else /* DB_VERSION_CHECK(2,0,0) */
	status = db->put(db, &q, &d, 0);
#endif /* DB_VERSION_CHECK(2,0,0) */

	pthread_mutex_unlock(&cache_lock);

	if (status == 0)
	{
		return 0;
	}
	else
	{
		*err = status;
		return -1;
	}
}

/*
**  DKIM_CACHE_EXPIRE -- expire records in an on-disk cache of entries
**
**  Parameters:
**  	db -- DB handle referring to the cache
**  	ttl -- time-to-live; delete any record older than this; if 0, apply
**  	       the TTL in the record
**  	err -- error code (returned)
**
**  Return value:
**  	-1 -- error; caller should check "err"
**  	otherwise -- count of deleted records
*/

int
dkim_cache_expire(DB *db, int ttl, int *err)
{
#if !DB_VERSION_CHECK(2,0,0)
	bool first = TRUE;
#endif /* ! DB_VERSION_CHECK(2,0,0) */
	bool delete;
	int deleted = 0;
	int status;
	time_t now;
#if DB_VERSION_CHECK(2,0,0)
	DBC *dbc;
#endif /* DB_VERSION_CHECK(2,0,0) */
	DBT q;
	DBT d;
	char name[DKIM_MAXHOSTNAMELEN + 1];
	struct dkim_cache_entry ce;

	assert(db != NULL);
	assert(err != NULL);

	memset(&q, '\0', sizeof q);
	memset(&d, '\0', sizeof d);

	(void) time(&now);

	pthread_mutex_lock(&cache_lock);

#if DB_VERSION_CHECK(2,0,0)
	status = db->cursor(db, NULL, &dbc, 0);
	if (status != 0)
	{
		*err = status;
		pthread_mutex_unlock(&cache_lock);
		return -1;
	}
#endif /* DB_VERSION_CHECK(2,0,0) */

	for (;;)
	{
		memset(name, '\0', sizeof name);
		memset(&ce, '\0', sizeof ce);

#if DB_VERSION_CHECK(3,0,0)
		q.data = name;
		q.flags = DB_DBT_USERMEM;
		q.ulen = sizeof name;
#endif /* DB_VERSION_CHECK(3,0,0) */

#if DB_VERSION_CHECK(3,0,0)
		d.data = (void *) &ce;
		d.flags = DB_DBT_USERMEM;
		d.ulen = sizeof ce;
#endif /* DB_VERSION_CHECK(3,0,0) */

#if DB_VERSION_CHECK(2,0,0)
		status = dbc->c_get(dbc, &q, &d, DB_NEXT);
		if (status == DB_NOTFOUND)
		{
			break;
		}
		else if (status != 0)
		{
			*err = status;
			break;
		}
#else /* DB_VERSION_CHECK(2,0,0) */
		status = db->seq(db, &q, &d, first ? R_FIRST : R_NEXT);
		if (status == DB_NOTFOUND)
		{
			break;
		}
		else if (status != 0)
		{
			*err = status;
			break;
		}

		first = FALSE;

		memcpy(name, q.data, MIN(sizeof name, q.size));
		memcpy((void *) &ce, d.data, MIN(sizeof ce, d.size));
#endif /* DB_VERSION_CHECK(2,0,0) */

		delete = FALSE;
		if (ttl == 0)
		{
			if (ce.cache_when + ce.cache_ttl < now)
				delete = TRUE;
		}
		else
		{
			if (ce.cache_when + ttl < now)
				delete = TRUE;
		}

		if (delete)
		{
#if DB_VERSION_CHECK(2,0,0)
			status = dbc->c_del(dbc, 0);
#else /* DB_VERSION_CHECK(2,0,0) */
			status = db->del(db, &q, R_CURSOR);
#endif /* DB_VERSION_CHECK(2,0,0) */
			if (status != 0)
			{
				*err = status;
				deleted = -1;
				break;
			}

			deleted++;
		}
	}

#if DB_VERSION_CHECK(2,0,0)
	(void) dbc->c_close(dbc);
#endif /* DB_VERSION_CHECK(2,0,0) */

	pthread_mutex_unlock(&cache_lock);

	return deleted;
}

/*
**  DKIM_CACHE_CLOSE -- close a cache database
**
**  Parameters:
**  	db -- cache DB handle
**
**  Return value:
**  	None.
*/

void
dkim_cache_close(DB *db)
{
	assert(db != NULL);

#if DB_VERSION_CHECK(2,0,0)
	(void) db->close(db, 0);
#else /* DB_VERSION_CHECK(2,0,0) */
	(void) db->close(db);
#endif /* DB_VERSION_CHECK(2,0,0) */

	(void) pthread_mutex_destroy(&cache_lock);
}

/*
**  DKIM_CACHE_STATS -- retrieve cache performance statistics
**
**  Parameters:
**  	queries -- number of queries handled (returned)
**  	hits -- number of cache hits (returned)
**  	expired -- number of expired hits (returned)
**
**  Return value:
**  	None.
**
**  Notes:
**  	Any of the parameters may be NULL if the corresponding datum
**  	is not of interest.
*/

void
dkim_cache_stats(DB *db, u_int *queries, u_int *hits, u_int *expired,
                 u_int *keys, _Bool reset)
{
	pthread_mutex_lock(&cache_stats_lock);

	if (queries != NULL)
		*queries = c_queries;

	if (hits != NULL)
		*hits = c_hits;

	if (expired != NULL)
		*expired = c_expired;

	if (keys != NULL)
	{
#if DB_VERSION_CHECK(2,0,0)
		DB_HASH_STAT *sp;

# if DB_VERSION_CHECK(4,3,0)
		if (db->stat(db, NULL, (void *) &sp, 0) != 0)
# elif DB_VERSION_CHECK(4,0,0)
		if (db->stat(db, (void *) &sp, 0) != 0)
# else /* DB_VERSION_CHECK(4,0,0) */
		if (db->stat(db, (void *) &sp, NULL, 0) != 0)
# endif /* DB_VERSION_CHECK(4,0,0) */
		{
			*keys = (u_int) -1;
		}
		else
		{
# if DB_VERSION_CHECK(3,0,0)
			*keys = sp->hash_nkeys;
# else /* DB_VERSION_CHECK(3,0,0) */
			*keys = sp->hash_nrecs;
# endif /* DB_VERSION_CHECK(3,0,0) */
			free(sp);
		}
#else /* DB_VERSION_CHECK(2,0,0) */
		*keys = (u_int) -1;
#endif /* DB_VERSION_CHECK(2,0,0) */
	}

	if (reset)
	{
		c_queries = 0;
		c_hits = 0;
		c_expired = 0;
	}

	pthread_mutex_unlock(&cache_stats_lock);
}

#endif /* QUERY_CACHE */
