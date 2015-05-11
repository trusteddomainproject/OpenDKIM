/*
**  Copyright (c) 2011-2013, 2015, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

#ifdef USE_ODBX
/* opendbx includes */
# include <odbx.h>
#endif /* USE_ODBX */

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendkim includes */
#include "config.h"
#include "stats.h"

/* definitions, macros, etc. */
#define	BUFRSZ		1024
#define	CMDLINEOPTS	"b:c:d:fh:o:p:P:r:s:u:vV"
#define	DEFDBBACKEND	SQL_BACKEND
#undef	DEFCONFFILE
#define	DEFCONFFILE	CONFIG_BASE "/opendkim-spam.conf"
#define	DEFDBHOST	"localhost"
#define	DEFDBNAME	"opendkim"
#define	DEFDBPASS	"opendkim"
#define	DEFDBPORT	""
#define	DEFDBSPAMCOL	"spam"
#define	DEFDBUSER	"opendkim"
#define	MAXHEADER	16384
#define SPACES		"\r\n\t "

#ifndef FALSE
# define FALSE		0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* ! TRUE */

/* globals */
char *progname;

/* config definition */
struct configdef spam_config[] =
{
	{ "Background",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "DatabaseBackend",		CONFIG_TYPE_STRING,	FALSE },
	{ "DatabaseHost",		CONFIG_TYPE_STRING,	FALSE },
	{ "DatabaseName",		CONFIG_TYPE_STRING,	FALSE },
	{ "DatabasePassword",		CONFIG_TYPE_STRING,	FALSE },
	{ "DatabaseSpamColumn",		CONFIG_TYPE_STRING,	FALSE },
	{ "DatabaseUser",		CONFIG_TYPE_STRING,	FALSE },
	{ "ReporterID",			CONFIG_TYPE_STRING,	FALSE },
	{ "SkipReceived",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "StatisticsFile",		CONFIG_TYPE_STRING,	FALSE },
	{ NULL,				(u_int) -1,		FALSE }
};

/*
**  USAGE -- usage message
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s [options]\n"
	        "\t-b backend  \tdatabase backend [%s]\n"
	        "\t-c file     \tconfiguration file [%s]\n"
	        "\t-d dbname   \tdatabase name [%s]\n"
	        "\t-f          \trun in the foreground\n"
	        "\t-h dbhost   \tdatabase hostname [%s]\n"
	        "\t-o file     \tstatistics file\n"
	        "\t-p dbpass   \tdatabase password [%s]\n"
	        "\t-P dbport   \tdatabase port [%s]\n"
	        "\t-s dbspamcol\tdatabase spam column name [%s]\n"
	        "\t-u dbuser   \tdatabase user [%s]\n"
		"\t-r reporter \treporter id (reporting host name)\n"
	        "\t-v          \tbe more verbose\n"
	        "\t-V          \tprint version number and exit\n",
	        progname, progname,
	        DEFDBBACKEND,
	        DEFCONFFILE,
	        DEFDBNAME,
	        DEFDBHOST,
	        DEFDBPASS,
	        DEFDBPORT,
	        DEFDBSPAMCOL,
	        DEFDBUSER);

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
	_Bool dofork = TRUE;
	int c;
	int verbose = 0;
	int dberr;
	int repid;
	int msgid;
	u_int skipcount = 0;
	char *p;
	char *prev;
	char *dbbackend = NULL;
	char *dbuser = NULL;
	char *dbpass = NULL;
	char *dbname = NULL;
	char *dbhost = NULL;
	char *dbspamcol = NULL;
	char *dbport = NULL;
	char *conffile = DEFCONFFILE;
	char *job = NULL;
	char *reporter = NULL;
	char *statsfile = NULL;
	FILE *sf;
	struct config *conf = NULL;
#ifdef USE_ODBX
	odbx_t *db = NULL;
	odbx_result_t *result;
#endif /* USE_ODBX */
	char buf[BUFRSZ + 1];
	char rcvd[MAXHEADER + 1];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'b':
			dbbackend = optarg;
			break;

		  case 'c':
			conffile = optarg;
			break;

		  case 'd':
			dbname = optarg;
			break;

		  case 'f':
			dofork = FALSE;
			break;

		  case 'h':
			dbhost = optarg;
			break;

		  case 'P':
			dbport = optarg;
			break;

		  case 'o':
			statsfile = optarg;
			break;

		  case 'p':
			dbpass = optarg;
			break;

		  case 's':
			dbspamcol = optarg;
			break;

		  case 'u':
			dbuser = optarg;
			break;

		  case 'r':
			reporter = optarg;
			break;

		  case 'v':
			verbose++;
			break;

		  case 'V':
			fprintf(stdout, "%s v%s\n", progname, VERSION);
			return EX_OK;

		  default:
			return usage();
		}
	}

	/* load from config file, if specified */
	if (conffile != NULL)
	{
		_Bool tmpf;
		unsigned int line;
		char path[MAXPATHLEN + 1];

		if (verbose >= 2)
		{
			fprintf(stdout, "%s: loading configuration from %s\n",
			        progname, conffile);
		}

		memset(path, '\0', sizeof path);
		conf = config_load(conffile, spam_config, &line,
		                   path, sizeof path, NULL);

		if (conf == NULL)
		{
			fprintf(stderr,
			        "%s: %s: configuration error at line %u: %s\n",
			        progname, path, line, config_error());
			return EX_CONFIG;

		}

		/* extract values */
		(void) config_get(conf, "SkipReceived",
		                  &skipcount, sizeof skipcount);

		if (dbbackend == NULL)
		{
			(void) config_get(conf, "DatabaseBackend",
			                  &dbbackend, sizeof dbbackend);
		}

		if (dbhost == NULL)
		{
			(void) config_get(conf, "DatabaseHost",
			                  &dbhost, sizeof dbhost);
		}

                if (dbname == NULL)
		{
			(void) config_get(conf, "DatabaseName",
			                  &dbname, sizeof dbname);
		}

		if (dbpass == NULL)
		{
			(void) config_get(conf, "DatabasePassword",
			                  &dbpass, sizeof dbpass);
		}

		if (dbport == NULL)
		{
			(void) config_get(conf, "DatabasePort",
			                  &dbport, sizeof dbport);
		}

		if (dbspamcol == NULL)
		{
			(void) config_get(conf, "DatabaseSpamColumn",
			                  &dbspamcol, sizeof dbspamcol);
		}

                if (dbuser == NULL)
		{
			(void) config_get(conf, "DatabaseUser",
			                  &dbuser, sizeof dbuser);
		}

		if (reporter == NULL)
		{
			(void) config_get(conf, "ReporterID",
			                  &reporter, sizeof reporter);
		}

		if (statsfile == NULL)
		{
			(void) config_get(conf, "StatisticsFile",
			                  &statsfile, sizeof statsfile);
		}

		if (config_get(conf, "Background", &tmpf, sizeof tmpf) == 1)
		{
			if (dofork && !tmpf)
				tmpf = FALSE;
		}
	}

	if (dbbackend == NULL)
		dbbackend = DEFDBBACKEND;
	if (dbhost == NULL)
		dbhost = DEFDBHOST;
	if (dbname == NULL)
		dbname = DEFDBNAME;
	if (dbpass == NULL)
		dbpass = DEFDBPASS;
	if (dbspamcol == NULL)
		dbspamcol = DEFDBSPAMCOL;
	if (dbuser == NULL)
		dbuser = DEFDBUSER;

	/* connect to the DB */
	if (statsfile != NULL)
	{
		sf = fopen(statsfile, "a");
		if (sf == NULL)
		{
			fprintf(stderr, "%s: %s: fopen(): %s\n", progname,
			        statsfile, strerror(errno));
			return EX_OSERR;
		}

		/* write version if file is new */
		if (ftell(sf) == 0)
			fprintf(sf, "V%d\n", DKIMS_VERSION);
	}
	else
	{
#ifndef USE_ODBX
		fprintf(stderr, "%s: SQL not supported in this installation\n",
		        progname);
		return EX_SOFTWARE;

#else /* ! USE_ODBX */

		dberr = odbx_init(&db, dbbackend, dbhost, dbport);
		if (dberr < 0)
		{
			fprintf(stderr, "%s: odbx_init(): %s\n", progname,
			        odbx_error(NULL, dberr));
			return EX_SOFTWARE;
		}

		if (verbose >= 1)
		{
			fprintf(stdout, "%s: connected to database on %s\n",
			        progname, dbhost);
		}

		dberr = odbx_bind(db, dbname, dbuser, dbpass,
		                  ODBX_BIND_SIMPLE);
		if (dberr < 0)
		{
			fprintf(stderr, "%s: odbx_bind(): %s\n", progname,
			        odbx_error(db, dberr));
			(void) odbx_finish(db);
			return EX_SOFTWARE;
		}

		if (verbose >= 2)
		{
			fprintf(stdout, "%s: database binding successful\n",
			        progname);
		}
#endif /* ! USE_ODBX */
	}

	/* read first Received:, extract reporter and job ID */
	memset(buf, '\0', sizeof buf);
	memset(rcvd, '\0', sizeof rcvd);
	while (fgets(buf, sizeof buf - 1, stdin) != NULL)
	{
		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\r' || *p == '\n')
			{
				*p = '\0';
				break;
			}
		}

		if (strncasecmp(buf, "Received:", 9) == 0)
		{
			if (skipcount > 0)
			{
				skipcount--;
				continue;
			}
			else
			{
				strlcpy(rcvd, buf, sizeof rcvd);
			}
		}
		else if (isascii(buf[0]) && isspace(buf[0]) &&
		         rcvd[0] != '\0')
		{
			strlcat(rcvd, buf, sizeof rcvd);
		}
		else if (isascii(buf[0]) && !isspace(buf[0]) &&
		         rcvd[0] != '\0')
		{
			break;
		}
	}

	if (rcvd[0] == '\0')
	{
		fprintf(stderr, "%s: Received header field not found\n",
		        progname);

#ifdef USE_ODBX
		if (db != NULL)
		{
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
		}
		else
		{
#endif /* USE_ODBX */
			fclose(sf);
#ifdef USE_ODBX
		}
#endif /* USE_ODBX */
		return EX_DATAERR;
	}

	/*
	**  This is overly simplistic as it doesn't account for CFWS or
	**  escapes, but for now it's a good starting point.
	*/

	prev = NULL;
	for (p = strtok(&rcvd[9], SPACES);
	     p != NULL;
	     p = strtok(NULL, SPACES))
	{
		if (prev != NULL)
		{
			if (strcasecmp(prev, "id") == 0)
				job = p;
			else if (reporter == NULL &&
			         strcasecmp(prev, "by") == 0)
				reporter = p;
		}

		prev = p;
	}

	if (job == NULL)
	{
		fprintf(stderr,
		        "%s: could not locate job ID in Received header field\n",
		        progname);

#ifdef USE_ODBX
		if (db != NULL)
		{
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
		}
		else
		{
#endif /* USE_ODBX */
			fclose(sf);
#ifdef USE_ODBX
		}
#endif /* USE_ODBX */
		return EX_DATAERR;
	}
	else if (reporter == NULL)
	{
		fprintf(stderr,
		        "%s: could not locate receiving host in Received header field\n",
		        progname);

#ifdef USE_ODBX
		if (db != NULL)
		{
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
		}
		else
		{
#endif /* USE_ODBX */
			fclose(sf);
#ifdef USE_ODBX
		}
#endif /* USE_ODBX */
		return EX_DATAERR;
	}

	for (p = job; *p != '\0'; p++)
	{
		if (*p == ';')
		{
			*p = '\0';
			break;
		}
	}

	if (sf != NULL)
	{
		fprintf(sf, "U%s\t%s\t0\t1\n", job, reporter);
		fclose(sf);
		return 0;
	}

#ifdef USE_ODBX
	if (verbose >= 1)
	{
		fprintf(stdout, "%s: requesting reporter id for '%s'\n",
		        progname, reporter);
	}

	if (dofork)
	{
		pid_t pid;

		pid = fork();
		switch (pid)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n",
			        progname, strerror(errno));
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_OSERR;

		  case 0:
			(void) setsid();
			/* XXX -- should probably dup2() /dev/null here */
			break;

		  default:
			return 0;
		}
	}

	/* retrieve reporter ID */
	snprintf(buf, sizeof buf, "SELECT id FROM reporters WHERE name = '%s'",
	         reporter);
	if (verbose >= 3)
		fprintf(stdout, ">>> %s\n", buf);

	dberr = odbx_query(db, buf, 0);
	if (dberr != ODBX_ERR_SUCCESS)
	{
		fprintf(stderr, "%s: odbx_query(): %s\n", progname,
		        odbx_error(db, dberr));
		(void) odbx_unbind(db);
		(void) odbx_finish(db);
		return EX_SOFTWARE;
	}

	repid = -1;

	while ((dberr = odbx_result(db, &result, NULL, 0)) != ODBX_RES_DONE)
	{
		if (dberr < 0)
		{
			fprintf(stderr, "%s: odbx_result(): %s\n",
			        progname, odbx_error(db, dberr));
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;
		}

		switch (dberr)
		{
		  case ODBX_RES_TIMEOUT:
			fprintf(stderr, "%s: odbx_result(): timeout\n",
			        progname);
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;

		  case ODBX_RES_NOROWS:
			fprintf(stderr,
			        "%s: odbx_result(): unexpected return value\n",
			        progname);
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;

		  case ODBX_RES_ROWS:
			while ((dberr = odbx_row_fetch(result)) != ODBX_ROW_DONE)
			{
				if (dberr < 0)
				{
					fprintf(stderr,
					        "%s: odbx_row_fetch(): %s\n",
						progname,
					        odbx_error(db, dberr));
					(void) odbx_unbind(db);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}

				if (repid != -1)
				{
					fprintf(stderr,
					        "%s: duplicate entries for repoter '%s'\n",
						progname,
					        reporter);
					(void) odbx_unbind(db);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}

				repid = atoi(odbx_field_value(result, 0));
				if (repid <= 0)
				{
					fprintf(stderr,
					        "%s: unexpected reporter id '%s'\n",
						progname,
					        odbx_field_value(result, 0));
					(void) odbx_unbind(db);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
			}

			break;

		  default:
			assert(0);
		}
	}

	(void) odbx_result_finish(result);

	if (repid <= 0)
	{
		fprintf(stderr,
		        "%s: could not determine reporter id for '%s'\n",
		        progname, reporter);

		(void) odbx_unbind(db);
		(void) odbx_finish(db);
		return EX_DATAERR;
	}

	if (verbose >= 2)
		fprintf(stdout, "%s: reporter id = %d\n", progname, repid);

	if (verbose >= 1)
	{
		fprintf(stdout, "%s: requesting message id for '%s'\n",
		        progname, job);
	}

	/* get message ID */
	snprintf(buf, sizeof buf,
	         "SELECT MAX(id) FROM messages WHERE jobid = '%s' AND reporter = %d",
	         job, repid);
	if (verbose >= 3)
		fprintf(stdout, ">>> %s\n", buf);
	dberr = odbx_query(db, buf, 0);
	if (dberr != ODBX_ERR_SUCCESS)
	{
		fprintf(stderr, "%s: odbx_query(): %s\n", progname,
		        odbx_error(db, dberr));
		(void) odbx_unbind(db);
		(void) odbx_finish(db);
		return EX_SOFTWARE;
	}

	msgid = -1;
	while ((dberr = odbx_result(db, &result, NULL, 0)) != ODBX_RES_DONE)
	{
		if (dberr < 0)
		{
			fprintf(stderr, "%s: odbx_result(): %s\n",
			        progname, odbx_error(db, dberr));
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;
		}

		switch (dberr)
		{
		  case ODBX_RES_TIMEOUT:
			fprintf(stderr, "%s: odbx_result(): timeout\n",
			        progname);
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;

		  case ODBX_RES_NOROWS:
			fprintf(stderr,
			        "%s: odbx_result(): unexpected return value\n",
			        progname);
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;

		  case ODBX_RES_ROWS:
			while ((dberr = odbx_row_fetch(result)) != ODBX_ROW_DONE)
			{
				if (dberr < 0)
				{
					fprintf(stderr,
					        "%s: odbx_row_fetch(): %s\n",
						progname,
					        odbx_error(db, dberr));
					(void) odbx_unbind(db);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}

				if (msgid != -1)
				{
					fprintf(stderr,
					        "%s: duplicate entries for job '%s' from reporter '%s'\n",
						progname,
					        job, reporter);
					(void) odbx_unbind(db);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}


				msgid = atoi(odbx_field_value(result, 0));
				if (msgid <= 0)
				{
					fprintf(stderr,
					        "%s: unexpected message id '%s'\n",
						progname,
					        odbx_field_value(result, 0));
					(void) odbx_unbind(db);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
			}

			break;

		  default:
			assert(0);
		}
	}

	(void) odbx_result_finish(result);

	if (msgid <= 0)
	{
		fprintf(stderr,
		        "%s: could not determine message id for '%s'\n",
		        progname, job);

		(void) odbx_unbind(db);
		(void) odbx_finish(db);
		return EX_DATAERR;
	}

	if (verbose >= 2)
		fprintf(stdout, "%s: message id = %d\n", progname, msgid);

	/* issue update */
	if (verbose >= 1)
		fprintf(stdout, "%s: updating record\n", progname);

	snprintf(buf, sizeof buf,
	         "UPDATE messages SET %s = %s + 1 WHERE id = %d AND %s >= 0",
	         dbspamcol, dbspamcol, msgid, dbspamcol);
	if (verbose >= 3)
		fprintf(stdout, ">>> %s\n", buf);
	dberr = odbx_query(db, buf, 0);
	if (dberr != ODBX_ERR_SUCCESS)
	{
		fprintf(stderr, "%s: odbx_query(): %s\n", progname,
		        odbx_error(db, dberr));
		(void) odbx_unbind(db);
		(void) odbx_finish(db);
		return EX_SOFTWARE;
	}

	for (;;)
	{
		dberr = odbx_result(db, &result, NULL, 0);
		if (dberr == ODBX_RES_DONE || dberr == ODBX_RES_NOROWS)
		{
			break;
		}
		else if (dberr < 0)
		{
			fprintf(stderr, "%s: odbx_result(): %s\n",
			        progname, odbx_error(db, dberr));
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;
		}

		switch (dberr)
		{
		  case ODBX_RES_TIMEOUT:
			fprintf(stderr, "%s: odbx_result(): timeout\n",
			        progname);
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;

		  case ODBX_RES_ROWS:
			fprintf(stderr,
			        "%s: odbx_result(): unexpected return value\n",
			        progname);
			(void) odbx_unbind(db);
			(void) odbx_finish(db);
			return EX_SOFTWARE;

		  default:
			assert(0);
		}
	}

	(void) odbx_result_finish(result);

	if (verbose >= 1)
		fprintf(stdout, "%s: record updated\n", progname);

	/* close down */
	(void) odbx_unbind(db);
	(void) odbx_finish(db);
#endif /* USE_ODBX */

	return 0;
}
