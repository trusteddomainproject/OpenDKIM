/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.c,v 1.10.2.4 2010/07/11 05:32:43 cm-msk Exp $
*/

#ifndef lint
static char stats_c_id[] = "@(#)$Id: stats.c,v 1.10.2.4 2010/07/11 05:32:43 cm-msk Exp $";
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
#include <stdlib.h>

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
**  	pcode -- policy code
**  	fromlist -- message appeared to be from a list
**  	rhcnt -- count of Received: header fields
**  	sa -- client socket information
**
**  Return value:
**  	0 on success, !0 on failure
*/

int
dkimf_stats_record(char *path, char *jobid, DKIM *dkimv, dkim_policy_t pcode,
                   _Bool fromlist, u_int rhcnt, struct sockaddr *sa)
{
	_Bool exists;
	_Bool sigfailed;
	_Bool sigfailedbody;
	_Bool sigpassed;
	_Bool validauthorsig = FALSE;
	int status = 0;
	int version;
	int nsigs;
	int err;
	int c;
	int ret = 0;
	off_t canonlen;
	off_t signlen;
	off_t msglen;
	DKIMF_DB db;
	char *from;
	char *p;
	char *dberr = NULL;
	DKIM_SIGINFO **sigs;
	struct dkim_stats_data_v2 recdata;
	struct dkimf_db_data dbd;

	assert(path != NULL);
	assert(jobid != NULL);

	/* open the DB */
	status = dkimf_db_open(&db, path, 0, &stats_lock, &dberr);
	if (status != 0)
	{
		if (dolog)
		{
			syslog(LOG_ERR, "%s: dkimf_db_open() failed: %s", path,
			       dberr);
		}

		return -1;
	}

	if (dkimf_db_type(db) != DKIMF_DB_TYPE_BDB)
	{
		(void) dkimf_db_close(db);

		if (dolog)
		{
			syslog(LOG_ERR,
			       "%s: invalid database type for this function",
			       path);
		}

		return -1;
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

		if (dkimf_db_close(db) != 0 && dolog)
		{
			char err[BUFRSZ];

			memset(err, '\0', sizeof err);
			(void) dkimf_db_strerror(db, err, sizeof err);
			syslog(LOG_ERR, "%s: dkimf_db_close() failed: %s",
			       path, err);
		}

		return -1;
	}

	/* check DB version */
	if (!exists || dbd.dbdata_buflen != sizeof version ||
	    version != DKIMF_STATS_VERSION)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: version check failed", path);

		if (dkimf_db_close(db) != 0 && dolog)
		{
			char err[BUFRSZ];

			memset(err, '\0', sizeof err);
			(void) dkimf_db_strerror(db, err, sizeof err);
			syslog(LOG_ERR, "%s: dkimf_db_close() failed: %s",
			       path, err);
		}

		return -1;
	}

	memset(&recdata, '\0', sizeof recdata);

	/* write info */
	status = dkim_getsiglist(dkimv, &sigs, &nsigs);
	if (status != DKIM_STAT_OK)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: dkim_getsiglist() failed", jobid);

		if (dkimf_db_close(db) != 0)
		{
			if (dolog)
			{
				char err[BUFRSZ];

				memset(err, '\0', sizeof err);
				(void) dkimf_db_strerror(db, err, sizeof err);
				syslog(LOG_ERR,
				       "%s: dkimf_db_close() failed: %s",
				       path, err);
			}

			ret = -1;
		}

		return ret;
	}

	from = dkim_getdomain(dkimv);
	if (from == NULL)
	{
		if (dkimf_db_close(db) != 0)
		{
			if (dolog)
			{
				char err[BUFRSZ];

				memset(err, '\0', sizeof err);
				(void) dkimf_db_strerror(db, err, sizeof err);
				syslog(LOG_ERR,
				       "%s: dkimf_db_close() failed: %s",
				       path, err);
			}

			ret = -1;
		}

		return ret;
	}

	strlcpy(recdata.sd_fromdomain, from, sizeof recdata.sd_fromdomain);
	recdata.sd_mailinglist = fromlist;
	recdata.sd_received = rhcnt;
	memcpy(&recdata.sd_sockinfo, sa, sizeof recdata.sd_sockinfo);

	(void) time(&recdata.sd_when);

	recdata.sd_totalsigs = nsigs;

	for (c = 0; c < nsigs; c++)
	{
		sigfailed = FALSE;
		sigfailedbody = FALSE;
		sigpassed = FALSE;

		if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PROCESSED) != 0)
		{
			if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) != 0 &&
			    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MATCH)
				sigpassed = TRUE;

			if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) == 0 ||
			    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH)
				sigfailed = TRUE;

			if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) == 0 &&
			    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH)
				sigfailedbody = TRUE;
		}

		if (sigpassed)
			recdata.sd_pass++;
		if (sigfailed)
			recdata.sd_fail++;
		if (sigfailedbody)
			recdata.sd_failbody++;

		if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_TESTKEY) != 0)
			recdata.sd_key_t++;

		p = dkim_sig_getdomain(sigs[c]);
		if (p != NULL)
		{
			if (strcasecmp(from, p) == 0)
			{
				recdata.sd_authorsigs++;
				if (sigfailed)
					recdata.sd_authorsigsfail++;
				else
					validauthorsig = TRUE;

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

		msglen = 0;
		canonlen = 0;
		signlen = 0;
		(void) dkim_sig_getcanonlen(dkimv, sigs[c], &msglen,
		                            &canonlen, &signlen);

		if (signlen != (off_t) -1)
		{
			recdata.sd_sig_l++;

			if (msglen > signlen)
				recdata.sd_extended++;
		}

		if (dkim_sig_gettagvalue(sigs[c], TRUE, "g") != NULL)
			recdata.sd_key_g++;

		p = dkim_sig_gettagvalue(sigs[c], FALSE, "t");
		if (p != NULL)
		{
			recdata.sd_sig_t++;

			if (strtoul(p, NULL, 10) > recdata.sd_when)
				recdata.sd_sig_t_future++;
		}

		if (dkim_sig_gettagvalue(sigs[c], FALSE, "x") != NULL)
			recdata.sd_sig_x++;

		if (dkim_sig_gettagvalue(sigs[c], FALSE, "z") != NULL)
			recdata.sd_sig_z++;

		err = dkim_sig_geterror(sigs[c]);

		switch (err)
		{
		  case DKIM_SIGERROR_NOKEY:
		  case DKIM_SIGERROR_KEYFAIL:
			recdata.sd_key_missing++;
			break;

		  case DKIM_SIGERROR_VERSION:
		  case DKIM_SIGERROR_DOMAIN:
		  case DKIM_SIGERROR_TIMESTAMPS:
		  case DKIM_SIGERROR_MISSING_C:
		  case DKIM_SIGERROR_INVALID_HC:
		  case DKIM_SIGERROR_INVALID_BC:
		  case DKIM_SIGERROR_MISSING_A:
		  case DKIM_SIGERROR_INVALID_A:
		  case DKIM_SIGERROR_MISSING_H:
		  case DKIM_SIGERROR_INVALID_L:
		  case DKIM_SIGERROR_INVALID_Q:
		  case DKIM_SIGERROR_INVALID_QO:
		  case DKIM_SIGERROR_MISSING_D:
		  case DKIM_SIGERROR_EMPTY_D:
		  case DKIM_SIGERROR_MISSING_S:
		  case DKIM_SIGERROR_EMPTY_S:
		  case DKIM_SIGERROR_MISSING_B:
		  case DKIM_SIGERROR_EMPTY_B:
		  case DKIM_SIGERROR_CORRUPT_B:
		  case DKIM_SIGERROR_DNSSYNTAX:
		  case DKIM_SIGERROR_MISSING_BH:
		  case DKIM_SIGERROR_EMPTY_BH:
		  case DKIM_SIGERROR_CORRUPT_BH:
		  case DKIM_SIGERROR_MULTIREPLY:
		  case DKIM_SIGERROR_EMPTY_H:
		  case DKIM_SIGERROR_TOOLARGE_L:
		  case DKIM_SIGERROR_KEYHASHMISMATCH:
		  case DKIM_SIGERROR_KEYDECODE:
			recdata.sd_key_syntax++;
			break;
		}
	}

	if (dkim_getpresult(dkimv) == DKIM_PRESULT_AUTHOR)
	{
		recdata.sd_adsp_found++;

		if (!validauthorsig)
		{
			if (pcode == DKIM_POLICY_ALL)
				recdata.sd_adsp_fail++;
			if (pcode == DKIM_POLICY_DISCARDABLE)
				recdata.sd_adsp_discardable++;
		}
	}

	/* write it out */
	status = dkimf_db_put(db, jobid, strlen(jobid), &recdata,
	                      sizeof recdata);
	if (status != 0)
	{
		char err[BUFRSZ];

		memset(err, '\0', sizeof err);
		(void) dkimf_db_strerror(db, err, sizeof err);
		syslog(LOG_ERR, "%s: dkimf_db_put() failed: %s", path, err);
	}

	/* close the DB */
	if (dkimf_db_close(db) != 0)
	{
		if (dolog)
		{
			char err[BUFRSZ];

			memset(err, '\0', sizeof err);
			(void) dkimf_db_strerror(db, err, sizeof err);
			syslog(LOG_ERR, "%s: dkimf_db_close() failed: %s",
			       path, err);
		}

		return -1;
	}

	return 0;
}
#endif /* _FFR_STATS */
