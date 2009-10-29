/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.c,v 1.6 2009/10/29 06:22:44 cm-msk Exp $
*/

#ifndef lint
static char stats_c_id[] = "@(#)$Id: stats.c,v 1.6 2009/10/29 06:22:44 cm-msk Exp $";
#endif /* !lint */

#ifdef _FFR_STATS

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
#include <dkim-strl.h>

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
dkimf_stats_record(char *path, const char *sigdomain,
                   dkim_canon_t hdrcanon, dkim_canon_t bodycanon,
                   dkim_alg_t signalg, bool passfail,
                   bool testing, bool lengths)
{
	int status = 0;
	DKIMF_DB db;
	DBT key;
	DBT data;
	size_t outlen;
	struct dkim_stats_key reckey;
	struct dkim_stats_data recdata;

	assert(path != NULL);
	assert(sigdomain != NULL);

	/* open the DB */
	status = dkimf_db_open(&db, path, 0, &stats_lock);

	if (status != 0)
	{
		if (dolog)
			syslog(LOG_ERR, "%s dkimf_db_open()", path);

		return;
	}

	/* populate the records */
	memset(&reckey, '\0', sizeof reckey);
	memset(&recdata, '\0', sizeof recdata);

	reckey.sk_hdrcanon = hdrcanon;
	reckey.sk_bodycanon = bodycanon;
	strlcpy(reckey.sk_sigdomain, sigdomain, sizeof reckey.sk_sigdomain);

	/* see if this key already exists */
	outlen = sizeof recdata;
	status = dkimf_db_get(db, &reckey, sizeof reckey, &recdata,
	                      &outlen, NULL);

	/* update totals */
	recdata.sd_lengths = lengths;
	(void) time(&recdata.sd_lastseen);
	recdata.sd_lastalg = signalg;
	if (passfail)
		recdata.sd_pass++;
	else
		recdata.sd_fail++;

	/* write it out */
	status = dkimf_db_put(db, &reckey, sizeof reckey, &recdata,
	                      sizeof recdata);

	/* close the DB */
	dkimf_db_close(db);
}
#endif /* _FFR_STATS */
