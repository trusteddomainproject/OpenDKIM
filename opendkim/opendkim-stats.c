/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-stats.c,v 1.2 2009/07/20 22:51:06 cm-msk Exp $
*/

#ifndef lint
static char opendkim_stats_c_id[] = "@(#)$Id: opendkim-stats.c,v 1.2 2009/07/20 22:51:06 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>

/* opendkim includes */
#include "opendkim-db.h"
#include "stats.h"

/* globals */
char *progname;
_Bool dolog = FALSE;			/* XXX -- dkim-db shouldn't use this */

/*
**  DKIMS_DUMP -- dump a database's contents
**
**  Parameters:
**  	path -- path to the database to dump
**
**  Return value:
**  	None.
*/

static void
dkims_dump(char *path)
{
#if ! DB_VERSION_CHECK(2,0,0)
	_Bool first = TRUE;
#endif /* ! DB_VERSION_CHECK(2,0,0) */
	int status = 0;
	DB *db;
	DBT key;
	DBT data;
#if DB_VERSION_CHECK(2,0,0)
	DBC *dbc;
#endif /* DB_VERSION_CHECK(2,0,0) */
	struct dkim_stats_key reckey;
	struct dkim_stats_data recdata;

	assert(path != NULL);

	/* open the DB */
	status = dkimf_db_open_ro(&db, path);

	if (status != 0)
	{
		char *err;

		err = DB_STRERROR(status);
		fprintf(stderr, "%s: %s: db->open(): %s\n", progname, path,
		        err);

		return;
	}

#if DB_VERSION_CHECK(2,0,0)
	/* establish a cursor */
	status = db->cursor(db, NULL, &dbc, 0);
	if (status != 0)
	{
		char *err;

		err = DB_STRERROR(status);
		fprintf(stderr, "%s: %s: db->cursor(): %s\n", progname, path,
		        err);
		DKIMF_DBCLOSE(db);
		return;
	}
#endif /* DB_VERSION_CHECK(2,0,0) */

	for (;;)
	{
		/* read next record */
		memset(&reckey, '\0', sizeof reckey);
		memset(&recdata, '\0', sizeof recdata);

		memset(&key, '\0', sizeof key);
		memset(&data, '\0', sizeof data);

#if DB_VERSION_CHECK(2,0,0)
		key.data = (void *) &reckey;
		key.flags = DB_DBT_USERMEM;
		key.ulen = sizeof reckey;
#endif /* DB_VERSION_CHECK(2,0,0) */

#if DB_VERSION_CHECK(2,0,0)
		data.data = (void *) &recdata;
		data.flags = DB_DBT_USERMEM;
		data.ulen = sizeof recdata;
#endif /* DB_VERSION_CHECK(2,0,0) */

#if DB_VERSION_CHECK(2,0,0)
		status = dbc->c_get(dbc, &key, &data, DB_NEXT);
		if (status == DB_NOTFOUND)
		{
			break;
		}
		else if (status != 0)
		{
			char *err;

			err = DB_STRERROR(status);
			fprintf(stderr, "%s: %s: dbc->c_get(): %s\n",
			        progname, path, err);
			dbc->c_close(dbc);
			DKIMF_DBCLOSE(db);
			return;
		}
#else /* DB_VERSION_CHECK(2,0,0) */
		status = db->seq(db, &key, &data, first ? R_FIRST : R_NEXT);
		if (status == DB_NOTFOUND)
		{
			break;
		}
		else if (status != 0)
		{
			fprintf(stderr, "%s: %s: db->seq(): %s\n",
			        progname, path, strerror(errno));
			DKIMF_DBCLOSE(db);
			return;
		}

		first = FALSE;

		memcpy((void *) &reckey, key.data,
		       MIN(sizeof reckey, key.size));
		memcpy((void *) &recdata, data.data,
		       MIN(sizeof recdata, key.size));
#endif /* DB_VERSION_CHECK(2,0,0) */

		/* dump record contents */
		fprintf(stdout,
		        "%s:%d/%d\t%lu pass/%lu fail, last l=%d, a=%d, %s",
		        reckey.sk_sigdomain,
		        reckey.sk_hdrcanon, reckey.sk_bodycanon,
		        recdata.sd_pass, recdata.sd_fail,
		        recdata.sd_lengths, recdata.sd_lastalg,
		        ctime(&recdata.sd_lastseen));
	}

	/* close database */
#if DB_VERSION_CHECK(2,0,0)
	(void) dbc->c_close(dbc);
#endif /* DB_VERSION_CHECK(2,0,0) */
	DKIMF_DBCLOSE(db);
}

/*
**  USAGE -- print usage message
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE
*/

static int
usage(void)
{
	fprintf(stderr, "%s: usage(): %s path\n", progname, progname);

	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	char *p;

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	if (argc != 2)
		return usage();

	dkims_dump(argv[1]);

	return EX_OK;
}
