/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-stats.c,v 1.7.8.3 2010/04/05 22:38:20 cm-msk Exp $
*/

#ifndef lint
static char opendkim_stats_c_id[] = "@(#)$Id: opendkim-stats.c,v 1.7.8.3 2010/04/05 22:38:20 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

/* openssl includes */
#include <openssl/sha.h>

/* opendkim includes */
#include "build-config.h"
#include "opendkim-db.h"
#include "stats.h"

/* macros */
#define	BUFRSZ		1024
#ifndef FALSE
# define FALSE		0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* ! TRUE */

#define	CMDLINEOPTS	"cim:r"
#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL	"/dev/null"
#endif /* ! _PATH_DEVNULL */
#ifndef _PATH_SENDMAIL
# define _PATH_SENDMAIL	"/usr/sbin/sendmail"
#endif /* ! _PATH_SENDMAIL */

/* globals */
_Bool csv;
char *progname;

/*
**  DKIMS_OUTPUT -- output a statistic
**
**  Parameters:
**  	out -- output
**  	label -- label
**  	v -- value
**  	m -- more?
**
**  Return value:
**  	None.
*/

static void
dkims_output(FILE *out, char *label, unsigned long value, _Bool more)
{
	assert(label != NULL);

	if (csv)
		fprintf(out, "%lu%s", value, more ? "\t" : "");
	else
		fprintf(out, "%s=%lu%s", label, value, more ? "," : "");
}

/*
**  DKIMS_DUMP -- dump a database's contents
**
**  Parameters:
**  	path -- path to the database to dump
**
**  Return value:
**  	An EX_* constant.
*/

static int
dkims_dump(char *path, char *mailto)
{
	_Bool first = TRUE;
	_Bool done = FALSE;
	int status = 0;
	int version = 1;
	size_t keylen;
	size_t datalen;
	DKIMF_DB db;
	FILE *out = stdout;
	struct dkim_stats_key_v1 reckey_v1;
	struct dkim_stats_data_v1 recdata_v1;
	struct dkim_stats_data_v2 recdata_v2;
	struct dkimf_db_data dbd;
	char jobid[DKIM_MAXHOSTNAMELEN + 1];

	assert(path != NULL);

	/* open the DB */
	status = dkimf_db_open(&db, path, DKIMF_DB_FLAG_READONLY, NULL);
	if (status != 0)
	{
		fprintf(stderr, "%s: %s: dkimf_db_open() failed\n",
		        progname, path);

		return EX_SOFTWARE;
	}

	/* determine version */
	dbd.dbdata_buffer = (char *) &version;
	dbd.dbdata_buflen = sizeof version;
	dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;
	status = dkimf_db_get(db, DKIMF_STATS_SENTINEL,
	                      sizeof(DKIMF_STATS_SENTINEL), &dbd, 1, NULL);
	if (status != 0)
	{
		fprintf(stderr, "%s: %s: dkimf_db_get() failed\n",
		        progname, path);

		dkimf_db_close(db);
		return EX_SOFTWARE;
	}

	if (mailto != NULL)
	{
		int devnull;
		int fds[2];
		pid_t child;
		time_t now;

		(void) time(&now);

		if (pipe(fds) != 0)
		{
			fprintf(stderr, "%s: pipe(): %s\n", progname,
			        strerror(errno));
			dkimf_db_close(db);
			return EX_OSERR;
		}

		out = fdopen(fds[1], "w");
		if (out == NULL)
		{
			fprintf(stderr, "%s: fdopen(): %s\n", progname,
			        strerror(errno));
			dkimf_db_close(db);
			return EX_OSERR;
		}

		devnull = open(_PATH_DEVNULL, O_RDWR, 0);
		if (devnull < 0)
		{
			fprintf(stderr, "%s: %s: open(): %s\n", progname,
			        _PATH_DEVNULL, strerror(errno));
			dkimf_db_close(db);
			return EX_OSERR;
		}

		child = fork();
		switch (child)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));
			close(devnull);
			dkimf_db_close(db);
			return EX_OSERR;

		  case 0:
			(void) dup2(fds[0], 0);
			(void) dup2(devnull, 1);
			(void) dup2(devnull, 2);
			close(devnull);
			close(fds[1]);
			dkimf_db_close(db);
			(void) execl(_PATH_SENDMAIL, _PATH_SENDMAIL, mailto,
			             NULL);
			exit(EX_OSERR);

		  default:
			close(devnull);
			close(fds[0]);

			/* MTA should add From: and Date: */
			fprintf(out, "To: %s\n", mailto);
			fprintf(out, "Subject: %s report at %ld\n",
			        progname, now);
			fprintf(out, "\n");

			fprintf(out, "Report-Time: %ld\n", now);
			fprintf(out, "Report-Version: %d\n", version);

			fprintf(out, "\n");

			break;
		}
	}

	while (!done)
	{
		switch (version)
		{
		  case 1:
			/* read next record */
			memset(&reckey_v1, '\0', sizeof reckey_v1);
			memset(&recdata_v1, '\0', sizeof recdata_v1);

			dbd.dbdata_buffer = (char *) &recdata_v1;
			dbd.dbdata_buflen = sizeof recdata_v1;
			dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;

			keylen = sizeof reckey_v1;
			datalen = sizeof recdata_v1;
			status = dkimf_db_walk(db, first, &reckey_v1, &keylen,
			                       &dbd, 1);
			if (status == 1)
			{
				done = TRUE;
				break;
			}
			else if (status == -1)
			{
				fprintf(stderr,
				        "%s: %s: dkimf_db_walk() failed\n",
				        progname, path);
				done = TRUE;
				break;
			}

			/* dump record contents */
			fprintf(out,
			        "%s:%d/%d\t%lu pass/%lu fail, last l=%d, a=%d, %s",
			        reckey_v1.sk_sigdomain,
			        reckey_v1.sk_hdrcanon, reckey_v1.sk_bodycanon,
			        recdata_v1.sd_pass, recdata_v1.sd_fail,
			        recdata_v1.sd_lengths, recdata_v1.sd_lastalg,
			        ctime(&recdata_v1.sd_lastseen));


			first = FALSE;
			break;

		  case 2:
			/* read next record */
			memset(jobid, '\0', sizeof jobid);
			memset(&recdata_v2, '\0', sizeof recdata_v2);

			dbd.dbdata_buffer = (char *) &recdata_v2;
			dbd.dbdata_buflen = sizeof recdata_v2;
			dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;

			keylen = sizeof jobid - 1;
			datalen = sizeof recdata_v1;
			status = dkimf_db_walk(db, first, jobid, &keylen,
			                       &dbd, 1);
			if (status == 1)
			{
				done = TRUE;
				break;
			}
			else if (status == -1)
			{
				fprintf(stderr,
				        "%s: %s: dkimf_db_walk() failed\n",
				        progname, path);
				done = TRUE;
				break;
			}

			/* dump record contents */
			if (csv)
				fprintf(out, "%s\t", jobid);
			else
				fprintf(out, "%s,", jobid);

			dkims_output(out, "when", recdata_v2.sd_when, TRUE);
			dkims_output(out, "alg", recdata_v2.sd_alg, TRUE);
			dkims_output(out, "hc", recdata_v2.sd_hdrcanon, TRUE);
			dkims_output(out, "bc", recdata_v2.sd_bodycanon, TRUE);
			dkims_output(out, "total", recdata_v2.sd_totalsigs,
			             TRUE);
			dkims_output(out, "pass", recdata_v2.sd_pass, TRUE);
			dkims_output(out, "fail", recdata_v2.sd_fail, TRUE);
			dkims_output(out, "failbody", recdata_v2.sd_failbody,
			             TRUE);
			dkims_output(out, "ext", recdata_v2.sd_extended, TRUE);
			dkims_output(out, "chgfrom", recdata_v2.sd_chghdr_from,
			             TRUE);
			dkims_output(out, "chgto", recdata_v2.sd_chghdr_to,
			             TRUE);
			dkims_output(out, "chgsubj",
			             recdata_v2.sd_chghdr_subject, TRUE);
			dkims_output(out, "chgother",
			             recdata_v2.sd_chghdr_other, TRUE);
			dkims_output(out, "keyt", recdata_v2.sd_key_t, TRUE);
			dkims_output(out, "keyg", recdata_v2.sd_key_g, TRUE);
			dkims_output(out, "keysyntax",
			             recdata_v2.sd_key_syntax, TRUE);
			dkims_output(out, "keynx", recdata_v2.sd_key_missing,
			             TRUE);
			dkims_output(out, "sigt", recdata_v2.sd_sig_t, TRUE);
			dkims_output(out, "sigtfut",
			             recdata_v2.sd_sig_t_future, TRUE);
			dkims_output(out, "sigx", recdata_v2.sd_sig_x, TRUE);
			dkims_output(out, "sigl", recdata_v2.sd_sig_l, TRUE);
			dkims_output(out, "sigz", recdata_v2.sd_sig_z, TRUE);
			dkims_output(out, "adsp", recdata_v2.sd_adsp_found,
			             TRUE);
			dkims_output(out, "adspfail", recdata_v2.sd_adsp_fail,
			             TRUE);
			dkims_output(out, "adspdisc",
			             recdata_v2.sd_adsp_discardable, TRUE);
			dkims_output(out, "asigs", recdata_v2.sd_authorsigs,
			             TRUE);
			dkims_output(out, "asigsfail",
			             recdata_v2.sd_authorsigsfail, TRUE);
			dkims_output(out, "tpsigs",
			             recdata_v2.sd_thirdpartysigs, TRUE);
			dkims_output(out, "tpsigsfail",
			             recdata_v2.sd_thirdpartysigsfail, TRUE);
			dkims_output(out, "mlist", recdata_v2.sd_mailinglist,
			             FALSE);

			fprintf(out, "\n");
				
			first = FALSE;
			break;

		  default:
			fprintf(stderr, "%s: %s: unknown version (%d)\n",
			        progname, path, version);
			done = TRUE;
			break;
		}
	}

	/* close database */
	dkimf_db_close(db);

	/* close output and wait if piped */
	if (out != stdout)
	{
		fclose(out);

		(void) wait(&status);

		if (WIFEXITED(status))
		{
			if (WEXITSTATUS(status) != 0)
			{
				fprintf(stderr, "%s: %s exited status %d\n",
				        progname, _PATH_SENDMAIL,
				        WEXITSTATUS(status));
			
				return EX_SOFTWARE;
			}
		}
		else if (WIFSIGNALED(status))
		{
			fprintf(stderr, "%s: %s terminated with signal %d\n",
			        progname, _PATH_SENDMAIL,
			        WTERMSIG(status));
		
			return EX_SOFTWARE;
		}
	}

	return EX_OK;
}

/*
**  DKIMS_INITDB -- initialize a stats DB
**
**  Parameters:
**  	path -- path to DB to create
**
**  Return value:
**  	An EX_* constant.
*/

static int
dkims_initdb(char *path)
{
	int status;
	int version;
	DKIMF_DB db;
	struct dkimf_db_data dbd;

	assert(path != NULL);

	/* fail if it already exists */
	if (access(path, W_OK) != 0)
	{
		fprintf(stderr, "%s: %s already exists\n", progname, path);
		return EX_SOFTWARE;
	}

	/* try to create */
	status = dkimf_db_open(&db, path, 0, NULL);
	if (status != 0)
	{
		fprintf(stderr, "%s: %s: dkimf_db_open() failed\n",
		        progname, path);

		return EX_SOFTWARE;
	}

	/* put a version record */
	version = DKIMF_STATS_VERSION;
	status = dkimf_db_put(db, DKIMF_STATS_SENTINEL,
	                      sizeof(DKIMF_STATS_SENTINEL),
	                      &version, sizeof version);
	if (status != 0)
	{
		fprintf(stderr, "%s: %s: dkimf_db_put() failed\n",
		        progname, path);
	}

	dkimf_db_close(db);
	return (status == 0 ? EX_OK : EX_SOFTWARE);
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
	fprintf(stderr, "%s: usage(): %s [options] path\n"
	                "\t-A     \tanonymize output\n"
	                "\t-i     \tinitialize database\n"
	                "\t-m addr\tmail report to specified address\n"
	                "\t-r     \treset database after sending report\n",
	        progname, progname);

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
	_Bool initdb = FALSE;
	_Bool resetdb = FALSE;
	int c;
	char *p;
	char *mailto = NULL;
	char *path = NULL;

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	csv = FALSE;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'c':
			csv = TRUE;
			break;

		  case 'i':
			initdb = TRUE;
			break;

		  case 'm':
			mailto = optarg;
			break;

		  case 'r':
			resetdb = TRUE;
			break;

		  default:
			return usage();
		}
	}

	if (argc == optind)
		return usage();
	else
		path = argv[optind];

	if (initdb)
	{
		return dkims_initdb(path);
	}
	else
	{
		int status;

		status = dkims_dump(path, mailto);
		if (status != 0 && resetdb)
		{
			if (unlink(path) != 0)
			{
				fprintf(stderr, "%s: %s: unlink(): %s\n",
				        progname, path, strerror(errno));

				return EX_OSERR;
			}
			else
			{
				return dkims_initdb(path);
			}
		}
	}
}
