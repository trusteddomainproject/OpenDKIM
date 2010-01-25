/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-stats.c,v 1.6.6.3 2010/01/25 23:20:00 cm-msk Exp $
*/

#ifndef lint
static char opendkim_stats_c_id[] = "@(#)$Id: opendkim-stats.c,v 1.6.6.3 2010/01/25 23:20:00 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>

/* opendkim includes */
#include "build-config.h"
#include "opendkim-db.h"
#include "stats.h"

/* macros */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */

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
	_Bool first = TRUE;
	int status = 0;
	size_t keylen;
	size_t datalen;
	DKIMF_DB db;
	struct dkim_stats_key reckey;
	struct dkim_stats_data recdata;
	struct dkimf_db_data dbd;

	assert(path != NULL);

	/* open the DB */
	status = dkimf_db_open(&db, path, 0, NULL);

	if (status != 0)
	{
		fprintf(stderr, "%s: %s: dkimf_db_open() failed\n",
		        progname, path);

		return;
	}

	for (;;)
	{
		/* read next record */
		memset(&reckey, '\0', sizeof reckey);
		memset(&recdata, '\0', sizeof recdata);

		dbd.dbdata_buffer = (char *) &recdata;
		dbd.dbdata_buflen = sizeof recdata;
		dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;

		keylen = sizeof reckey;
		datalen = sizeof recdata;
		status = dkimf_db_walk(db, first, &reckey, &keylen,
		                       &dbd, 1);
		if (status == 1)
		{
			break;
		}
		else if (status == -1)
		{
			fprintf(stderr, "%s: %s: dkimf_db_walk() failed\n",
			        progname, path);
			break;
		}

		/* dump record contents */
		fprintf(stdout,
		        "%s:%d/%d\t%lu pass/%lu fail, last l=%d, a=%d, %s",
		        reckey.sk_sigdomain,
		        reckey.sk_hdrcanon, reckey.sk_bodycanon,
		        recdata.sd_pass, recdata.sd_fail,
		        recdata.sd_lengths, recdata.sd_lastalg,
		        ctime(&recdata.sd_lastseen));

		first = FALSE;
	}

	/* close database */
	dkimf_db_close(db);
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
