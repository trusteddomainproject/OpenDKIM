/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.c,v 1.1 2009/07/16 20:59:11 cm-msk Exp $
*/

#ifdef _FFR_STATS

#ifndef lint
static char stats_c_id[] = "@(#)$Id: stats.c,v 1.1 2009/07/16 20:59:11 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <assert.h>
#include <syslog.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim ncludes */
#include "stats.h"
#include "opendkim.h"
#include "opendkim-db.h"

/* globals */
static pthread_mutex_t stats_lock;

/*
**  DKIMF_STATS_INIT -- initialize statistics
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
dkimf_stats_init(void)
{
	pthread_mutex_init(&stats_lock, NULL);
}

/*
**  DKIMF_STATS_RECORD -- record a DKIM result
**
**  Parameters:
**  	path -- patth to the DB to update
**  	sigdomain -- signing domain
**  	hdrcanon -- header canonicalization used
**  	bodycanon -- body canonicalization used
**  	signalg -- signing algorithm used
**  	passfail -- result (TRUE == pass, FALSE == not pass)
**  	testing -- testing?
**  	lengths -- l= tag present?
**
**  Return value:
**  	None (for now).
*/

void
dkimf_stats_record(const char *path, const char *sigdomain,
                   dkim_canon_t hdrcanon, dkim_canon_t bodycanon,
                   dkim_alg_t signalg, bool passfail,
                   bool testing, bool lengths)
{
	int status = 0;
	DB *db;
	DBT key;
	DBT data;
	struct dkim_stats_key reckey;
	struct dkim_stats_data recdata;

	assert(path != NULL);
	assert(sigdomain != NULL);

	pthread_mutex_lock(&stats_lock);

	/* open the DB */
	status = dkimf_db_open_rw(&db, path);

	if (status != 0)
	{
		if (dolog)
		{
			char *err;

			err = DB_STRERROR(status);
			syslog(LOG_ERR, "%s: db->open(): %s", path, err);
		}

		pthread_mutex_unlock(&stats_lock);

		return;
	}

	/* populate the records */
	memset(&reckey, '\0', sizeof reckey);
	memset(&recdata, '\0', sizeof recdata);

	reckey.sk_hdrcanon = hdrcanon;
	reckey.sk_bodycanon = bodycanon;
	sm_strlcpy(reckey.sk_sigdomain, sigdomain, sizeof reckey.sk_sigdomain);

	/* see if this key already exists */
	memset(&key, '\0', sizeof key);
	memset(&data, '\0', sizeof data);

	key.data = (void *) &reckey;
	key.size = sizeof reckey;
#if DB_VERSION_CHECK(2,0,0)
	key.ulen = sizeof reckey;
	key.flags = DB_DBT_USERMEM;
#endif /* DB_VERSION_CHECK(2,0,0) */

	data.data = (void *) &recdata;
	data.size = sizeof recdata;
#if DB_VERSION_CHECK(2,0,0)
	data.ulen = sizeof recdata;
	data.flags = DB_DBT_USERMEM;
#endif /* DB_VERSION_CHECK(2,0,0) */

#if DB_VERSION_CHECK(2,0,0)
	status = db->get(db, NULL, &key, &data, 0);
#else /* DB_VERSION_CHECK(2,0,0) */
	status = db->get(db, &key, &data, 0);
#endif /* DB_VERSION_CHECK(2,0,0) */
	if (status != DB_NOTFOUND && status != 0)
	{
		if (dolog)
		{
			char *err;

			err = DB_STRERROR(status);
			syslog(LOG_ERR, "%s: db->get(): %s", path, err);
		}

		DKIMF_DBCLOSE(db);

		pthread_mutex_unlock(&stats_lock);

		return;
	}

#if !DB_VERSION_CHECK(2,0,0)
	memcpy((void *) &recdata, data.data, MIN(sizeof recdata, data.size));
#endif /* ! DB_VERSION_CHECK(2,0,0) */

	/* update totals */
	recdata.sd_lengths = lengths;
	(void) time(&recdata.sd_lastseen);
	recdata.sd_lastalg = signalg;
	if (passfail)
		recdata.sd_pass++;
	else
		recdata.sd_fail++;

	/* write/update the record */
	memset(&key, '\0', sizeof key);
	memset(&data, '\0', sizeof data);

	key.data = (void *) &reckey;
	key.size = sizeof reckey;
#if DB_VERSION_CHECK(2,0,0)
	key.ulen = sizeof reckey;
	key.flags = DB_DBT_USERMEM;
#endif /* DB_VERSION_CHECK(2,0,0) */

	data.data = (void *) &recdata;
	data.size = sizeof recdata;
#if DB_VERSION_CHECK(2,0,0)
	data.ulen = sizeof recdata;
	data.flags = DB_DBT_USERMEM;
#endif /* DB_VERSION_CHECK(2,0,0) */

#if DB_VERSION_CHECK(2,0,0)
	status = db->put(db, NULL, &key, &data, 0);
#else /* DB_VERSION_CHECK(2,0,0) */
	status = db->put(db, &key, &data, 0);
#endif /* DB_VERSION_CHECK(2,0,0) */
	if (status != 0 && dolog)
	{
		char *err;

		err = DB_STRERROR(status);
		syslog(LOG_ERR, "%s: db->put(): %s", path, err);
	}

	/* close the DB */
	DKIMF_DBCLOSE(db);

	pthread_mutex_unlock(&stats_lock);
}

#endif /* _FFR_STATS */
