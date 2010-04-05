/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.c,v 1.8.8.1 2010/04/05 23:27:00 cm-msk Exp $
*/

#ifndef lint
static char stats_c_id[] = "@(#)$Id: stats.c,v 1.8.8.1 2010/04/05 23:27:00 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

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
**  	path -- path to the DB to update
**  	jobid -- job ID for the current message
**  	dkimv -- verifying handle from which data can be taken
**  	fromlist -- message appeared to be from a list
**
**  Return value:
**  	None (for now).
*/

void
dkimf_stats_record(char *path, char *jobid, DKIM *dkimv, _Bool fromlist)
{
	_Bool exists;
	_Bool sigfailed;
	_Bool sigfailedbody;
	_Bool sigpassed;
	int status = 0;
	int version;
	int nsigs;
	int c;
	DBT key;
	DBT data;
	DKIMF_DB db;
	char *from;
	char *p;
	DKIM_SIGINFO **sigs;
	size_t outlen;
	struct dkim_stats_data_v2 recdata;
	struct dkimf_db_data dbd;

	assert(path != NULL);
	assert(jobid != NULL);

	/* open the DB */
	status = dkimf_db_open(&db, path, 0, &stats_lock);
	if (status != 0)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: dkimf_db_open() failed", path);

		return;
	}

	/* see if there's a sentinel record; if not, bail */
	dbd.dbdata_buffer = (void *) &version;
	dbd.dbdata_buflen = sizeof version;
	dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;
	exists = FALSE;
	status = dkimf_db_get(db, DKIMF_STATS_SENTINEL,
	                      sizeof(DKIMF_STATS_SENTINEL), &dbd, 1, &exists);
	if (status != 0)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: dkimf_db_get() failed", path);

		dkimf_db_close(db);
		return;
	}

	/* check DB version */
	if (!exists || dbd.dbdata_buflen != sizeof version ||
	    version != DKIMF_STATS_VERSION)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: version check failed", path);

		dkimf_db_close(db);
		return;
	}

	/* write info */
	status = dkim_getsiglist(dkimv, &sigs, &nsigs);
	if (status != DKIM_STAT_OK)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: dkim_getsiglist() failed", jobid);

		dkimf_db_close(db);
		return;
	}
	else if (nsigs == 0)
	{
		dkimf_db_close(db);
		return;
	}

	from = dkim_getdomain(dkimv);
	if (from == NULL)
	{
		dkimf_db_close(db);
		return;
	}

	recdata.sd_mailinglist = fromlist;

	(void) time(&recdata.sd_when);

	recdata.sd_totalsigs = nsigs;

	for (c = 0; c < nsigs; c++)
	{
		sigfailed = FALSE;
		sigfailedbody = FALSE;
		sigpassed = FALSE;

		if (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PROCESSED != 0)
		{
			if (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED != 0 &&
			    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MATCH)
				sigpassed = TRUE;

			if (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED == 0 ||
			    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH)
				sigfailed = TRUE;

			if (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED != 0 ||
			    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH)
				sigfailedbody = TRUE;
		}

		if (sigpassed)
			recdata.sd_pass++;
		if (sigfailed)
			recdata.sd_fail++;
		if (sigfailedbody)
			recdata.sd_failbody++;

		p = dkim_sig_getdomain(sigs[c]);
		if (p != NULL)
		{
			if (strcasecmp(from, p) == 0)
			{
				recdata.sd_authorsigs++;
				if (sigfailed)
					recdata.sd_authorsigsfail++;

				(void) dkim_sig_getcanons(sigs[c],
				                          &recdata.sd_hdrcanon,
				                          &recdata.sd_bodycanon);

				(void) dkim_sig_getsignalg(sigs[c],
				                           &recdata.sd_alg);
			}
			else
			{
				recdata.sd_thirdpartysigs++;
				if (sigfailed)
					recdata.sd_thirdpartysigsfail++;
			}
		}
	}

#if 0
	/* XXX -- FINISH THESE */
	u_int		sd_extended;
	u_int		sd_chghdr_from;
	u_int		sd_chghdr_to;
	u_int		sd_chghdr_subject;
	u_int		sd_chghdr_other;
	u_int		sd_key_t;
	u_int		sd_key_g;
	u_int		sd_key_syntax;
	u_int		sd_key_missing;
	u_int		sd_sig_t;
	u_int		sd_sig_t_future;
	u_int		sd_sig_x;
	u_int		sd_sig_l;
	u_int		sd_sig_z;
	u_int		sd_adsp_found;
	u_int		sd_adsp_fail;
	u_int		sd_adsp_discardable;
#endif /* 0 */

	/* write it out */
	status = dkimf_db_put(db, jobid, strlen(jobid), &recdata,
	                      sizeof recdata);

	/* close the DB */
	dkimf_db_close(db);
}
#endif /* _FFR_STATS */
