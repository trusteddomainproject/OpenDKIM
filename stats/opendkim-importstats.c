/*
**  Copyright (c) 2010-2013, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sysexits.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_GETOPT_LONG
# define _GNU_SOURCE
# include <getopt.h>
#endif /* HAVE_GETOPT_LONG */

/* OpenDKIM includes */
#include "stats.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* libodbx includes */
#ifdef USE_ODBX
# include <odbx.h>
#else /* USE_ODBX */
# error OpenDBX is required for opendkim-importstats
#endif /* USE_ODBX */

/* macros, definitions */
#define	CMDLINEOPTS	"d:EFh:mP:p:rSs:u:vx"

#define	DEFDBHOST	"localhost"
#define	DEFDBNAME	"opendkim"
#define	DEFDBSCHEME	SQL_BACKEND
#define	DEFDBUSER	"opendkim"

#define	MAXLINE		2048
#define	MAXREPORTER	256

/* data structures */
struct table
{
	char *		tbl_left;
	char *		tbl_right;
};

/* globals */
char *progname;
char reporter[MAXREPORTER + 1];
int verbose;

struct table last_insert_id[] =
{
	{ "mysql",	"LAST_INSERT_ID()" },
	{ "sqlite3",	"LAST_INSERT_ROWID()" },
	{ "pgsql",	"LASTVAL()" },
	{ NULL,		NULL }
};

#ifdef HAVE_GETOPT_LONG
/* getopt long option names */
struct option long_option[] =
{
	{ "dbhost",	required_argument,	NULL,	'h' },
	{ "dbname",	required_argument,	NULL,	'd' },
	{ "dbpasswd",	required_argument,	NULL,	'p' },
	{ "dbport",	required_argument,	NULL,	'P' },
	{ "dbscheme",	required_argument,	NULL,	's' },
	{ "dbuser",	required_argument,	NULL,	'u' },
	{ "verbose",	required_argument,	NULL,	'v' },
	{ NULL,		0,			NULL,	'\0' }
};
#endif /* HAVE_GETOPT_LONG */

/*
**  SANITIZE -- sanitize a string
**
**  Parameters:
**  	db -- DB handle
**  	in -- input string
**  	out -- output buffer
**  	len -- bytes available at "out"
**
**  Return value:
**  	0 == string was safe
**  	1 == string was not safe
*/

int
sanitize(odbx_t *db, char *in, char *out, size_t len)
{
	unsigned long outlen;

	assert(db != NULL);
	assert(in != NULL);
	assert(out != NULL);

	memset(out, '\0', len);

	outlen = len;

	(void) odbx_escape(db, in, strlen(in), out, &outlen);

	return (strncmp(in, out, (size_t) outlen) != 0);
}

/*
**  DUMPFIELDS -- dump array of fields for debugging
**
**  Parameters:
**  	out -- output stream
**  	fields -- array of fields
**  	n -- length of fields array
**
**  Return value:
**  	None.
*/

void
dumpfields(FILE *out, char **fields, int n)
{
	int c;

	for (c = 0; c < n; c++)
		fprintf(out, "\t%d = '%s'\n", c, fields[c]);
}

/*
**  FINDINLIST -- see if a particular string appears in another list
**
**  Parameters:
**  	str -- string to find
**  	list -- colon-separated list of strings to search
**
**  Return value:
**  	1 -- "str" found in "list"
**  	0 -- "str" not found in "list"
*/

int
findinlist(char *str, char *list)
{
	int len;
	char *p;
	char *q;

	assert(str != NULL);
	assert(list != NULL);

	len = strlen(str);

	q = list;

	for (p = list; ; p++)
	{
		if (*p == ':' || *p == '\0')
		{
			if (p - q == len && strncasecmp(str, q, len) == 0)
				return 1;

			q = p + 1;
		}

		if (*p == '\0')
			break;
	}

	return 0;
}

/*
**  SQL_MKTIME -- convert a UNIX time_t (as a string) to an SQL time string
**
**  Parameters:
**  	in -- input time
**  	out -- output buffer
**  	outlen -- bytes available at "out"
**
**  Return value:
**  	0 -- error
**  	>0 -- bytes of "out" used
*/

int
sql_mktime(const char *in, char *out, size_t outlen)
{
	time_t convert;
	struct tm *local;
	char *p;

	assert(in != NULL);
	assert(out != NULL);

	errno = 0;
	convert = strtoul(in, &p, 10);
	if (errno != 0 || *p != '\0')
		return 0;

	local = localtime(&convert);

	return strftime(out, outlen, "%Y-%m-%d %H:%M:%S", local);
}

/*
**  SQL_GET_INT -- retrieve a single integer from an SQL query
**
**  Parameters:
**  	db -- DB handle
**  	sql -- SQL query to perform
**
**  Return value:
**  	-1 -- error
**  	0 -- no record matched
**  	1 -- extracted value
*/

int
sql_get_int(odbx_t *db, char *sql)
{
	int out = 0;
	int err;
	odbx_result_t *result = NULL;

	assert(db != NULL);
	assert(sql != NULL);

	if (verbose > 0)
		fprintf(stderr, "> %s\n", sql);

	err = odbx_query(db, sql, strlen(sql));
	if (err < 0)
	{
		fprintf(stderr, "%s: odbx_query(): %s\n",
		        progname, odbx_error(db, err));
		return -1;
	}

	err = odbx_result(db, &result, NULL, 0);
	if (err < 0)
	{
		fprintf(stderr, "%s: odbx_result(): %s\n",
		        progname, odbx_error(db, err));
		return -1;
	}

	for (;;)
	{
		err = odbx_row_fetch(result);
		if (err == ODBX_ROW_DONE)
		{
			break;
		}
		else if (err < 0)
		{
			fprintf(stderr, "%s: odbx_row_fetch(): %s\n",
			        progname, odbx_error(db, err));
			return -1;
		}

		if (out == 0)
		{
			char *p;
			const char *op;

			op = odbx_field_value(result, 0);
			if (op == NULL)
			{
				fprintf(stderr, "%s: unexpected NULL value\n",
				        progname);
				odbx_result_finish(result);
				return -1;
			}

			out = strtol(op, &p, 10);
			if (*p != '\0')
			{
				fprintf(stderr, "%s: malformed integer\n",
				        progname);
				odbx_result_finish(result);
				return -1;
			}
		}
	}

	odbx_result_finish(result);

	return out;
}

/*
**  SQL_DO -- perform an SQL operation with no result
**
**  Parameters:
**  	db -- DB handle
**  	sql -- SQL action to perform
**
**  Return value:
**  	-1 -- error
**  	0 -- success
*/

int
sql_do(odbx_t *db, char *sql)
{
	int err;
	odbx_result_t *result = NULL;

	assert(db != NULL);
	assert(sql != NULL);

	if (verbose > 0)
		fprintf(stderr, "> %s\n", sql);

	err = odbx_query(db, sql, strlen(sql));
	if (err < 0)
	{
		fprintf(stderr, "%s: odbx_query(): %s\n",
		        progname, odbx_error(db, err));
		return -1;
	}

	err = odbx_result(db, &result, NULL, 0);
	if (err < 0)
	{
		fprintf(stderr, "%s: odbx_result(): %s\n",
		        progname, odbx_error(db, err));
		return -1;
	}

	if (err != 2)
		return -1;

	odbx_result_finish(result);

	return 0;
}

/*
**  USAGE -- print usage message and exit
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
#ifdef HAVE_GETOPT_LONG
	                "\t-d, --dbname=name    \tdatabase name (default: \"%s\")\n"
	                "\t-E                   \tinput errors are fatal\n"
	                "\t-F                   \tdump parsed fields on errors\n"
	                "\t-h, --dbhost=host    \tdatabase host/address (default: \"%s\")\n"
	                "\t-m                   \tinput is in email format\n"
	                "\t-P, --dbport=port    \tdatabase port\n"
	                "\t-p, --dbpasswd=passwd\tdatabase password\n"
	                "\t-r                   \tdon't add unknown reporters\n"
	                "\t-S                   \tdon't skip duplicate messages\n"
	                "\t-s, --dbscheme=scheme\tdatabase scheme (default: \"%s\")\n"
	                "\t-u, --dbuser=user    \tdatabase user (default: \"%s\")\n"
	                "\t-v, --verbose        \tincrease verbose output\n"
# ifdef _FFR_STATSEXT
	                "\t-x                   \timport extension records\n"
# endif /* _FFR_STATSEXT */

#else /* HAVE_GETOPT_LONG */

	                "\t-d name  \tdatabase name (default: \"%s\")\n"
	                "\t-E       \tinput errors are fatal\n"
	                "\t-F       \tdump parsed fields on errors\n"
	                "\t-h host  \tdatabase host/address (default: \"%s\")\n"
	                "\t-m       \tinput is in email format\n"
	                "\t-P port  \tdatabase port\n"
	                "\t-p passwd\tdatabase password\n"
	                "\t-r       \tdon't add unknown reporters\n"
	                "\t-S       \tdon't skip duplicate messages\n"
	                "\t-s scheme\tdatabase scheme (default: \"%s\")\n"
	                "\t-u user  \tdatabase user (default: \"%s\")\n"
	                "\t-v       \tincrease verbose output\n"
# ifdef _FFR_STATSEXT
	                "\t-x       \timport extension records\n"
# endif /* _FFR_STATSEXT */
#endif /* HAVE_GETOPT_LONG */
	        ,
	        progname, progname, DEFDBNAME, DEFDBHOST, DEFDBSCHEME,
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
	int c;
	int n;
#ifdef _FFR_STATSEXT
	int extensions = 0;
#endif /* _FFR_STATSEXT */
	int nfields = 0;
	int line;
	int err;
	int mail = 0;
	int dontskip = 0;
	int fatalerrors = 0;
	int showfields = 0;
	int skipsigs = 0;
	int norepadd = 0;
	int repid;
	int domid;
	int addrid;
	int msgid;
	int sigid;
	int inversion = -1;
#ifdef HAVE_GETOPT_LONG
	int long_opt_index = 0;
#endif /* HAVE_GETOPT_LONG */
	char *p;
	char *lastrow = NULL;
	char *dbhost = DEFDBHOST;
	char *dbname = DEFDBNAME;
	char *dbscheme = DEFDBSCHEME;
	char *dbuser = DEFDBUSER;
	char *dbpassword = NULL;
	char *dbport = NULL;
	char **fields = NULL;
	odbx_t *db = NULL;
	char buf[MAXLINE + 1];
	char timebuf[MAXLINE + 1];
	char sql[MAXLINE + 1];
	char safesql[MAXLINE * 2 + 1];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	verbose = 0;

#ifdef HAVE_GETOPT_LONG
	while ((c = getopt_long(argc, argv, CMDLINEOPTS,
	                        long_option, &long_opt_index)) != -1)
#else /* HAVE_GETOPT_LONG */
	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
#endif /* HAVE_GETOPT_LONG */
	{
		switch (c)
		{
		  case 'd':
			dbname = optarg;
			break;

		  case 'E':
			fatalerrors = 1;
			break;

		  case 'F':
			showfields = 1;
			break;

		  case 'h':
			dbhost = optarg;
			break;

		  case 'm':
			mail = 1;
			break;

		  case 'P':
			dbport = optarg;
			break;

		  case 'p':
			dbpassword = optarg;
			break;

		  case 'r':
			norepadd = 1;
			break;

		  case 'S':
			dontskip = 1;
			break;

		  case 's':
			dbscheme = optarg;
			break;

		  case 'u':
			dbuser = optarg;
			break;

		  case 'v':
			verbose++;
			break;

#ifdef _FFR_STATSEXT
		  case 'x':
			extensions = 1;
			break;
#endif /* _FFR_STATSEXT */

		  default:
			return usage();
		}
	}

	for (c = 0; ; c++)
	{
		if (strcasecmp(last_insert_id[c].tbl_left, dbscheme) == 0)
		{
			lastrow = last_insert_id[c].tbl_right;
			break;
		}
	}

	if (lastrow == NULL)
	{
		fprintf(stderr, "%s: scheme \"%s\" not currently supported\n",
		        progname, dbscheme);
		return EX_SOFTWARE;
	}

	/* try to connect to the database */
	if (odbx_init(&db, dbscheme, dbhost, dbport) < 0)
	{
		fprintf(stderr, "%s: odbx_init() failed\n", progname);
		return EX_TEMPFAIL;
	}

	/* bind with user, password, database information */
	err = odbx_bind(db, dbname, dbuser, dbpassword, ODBX_BIND_SIMPLE);
	if (err < 0)
	{
		fprintf(stderr, "%s: odbx_bind(): %s\n", progname,
		        odbx_error(db, err));
		(void) odbx_finish(db);
		return EX_TEMPFAIL;
	}

	/* initialize stuff */
	memset(buf, '\0', sizeof buf);
	memset(reporter, '\0', sizeof reporter);
	line = 0;
	repid = 0;
	msgid = 0;
	sigid = 0;

	/* read lines from stdin */
	while (fgets(buf, sizeof buf - 1, stdin) != NULL)
	{
		line++;

		/* eat the newline */
		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n')
			{
				*p = '\0';
				break;
			}
		}

		if (mail == 1)
		{
			if (strlen(buf) > 0)
				continue;

			mail = 0;
			continue;
		}

		/* first byte identifies the record type */
		c = buf[0];

		/* reset fields array */
		if (fields != NULL)
			memset(fields, '\0', sizeof(char *) * nfields);

		/* now break out the fields */
		n = 0;
		for (p = strtok(buf + 1, "\t");
		     p != NULL;
		     p = strtok(NULL, "\t"))
		{
			if (nfields == n)
			{
				int newnf;
				size_t newsz;
				char **new;

				newnf = MAX(nfields * 2, 8);
				newsz = sizeof(char *) * newnf;

				if (nfields == 0)
					new = (char **) malloc(newsz);
				else
					new = (char **) realloc(fields, newsz);

				if (new == NULL)
				{
					fprintf(stderr,
					        "%s: %salloc(): %s\n",
					        progname,
					        fields == NULL ? "m" : "re",
					        strerror(errno));
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}

				nfields = newnf;
				fields = new;
			}

			fields[n++] = p;
		}

		sigid = 0;

		/* processing section for messages */
		if (c == '\0')
		{
			continue;
		}
		else if (c == 'V')
		{
			if (n != 1)
			{
				fprintf(stderr,
				        "%s: unexpected version field count (%d) at input line %d\n",
				        progname, n, line);

				if (showfields == 1)
					dumpfields(stderr, fields, n);

				if (fatalerrors == 1)
				{
					(void) odbx_finish(db);
					return EX_DATAERR;
				}

				continue;
			}

			inversion = atoi(fields[0]);
		}
		else if (c == 'M')
		{
			if (inversion != DKIMS_VERSION)
			{
				fprintf(stderr,
				        "%s: ignoring old format at input line %d\n",
				        progname, line);

				continue;
			}

			if (n != DKIMS_MI_MAX + 1)
			{
				fprintf(stderr,
				        "%s: unexpected message field count (%d) at input line %d\n",
				        progname, n, line);

				if (showfields == 1)
					dumpfields(stderr, fields, n);

				if (fatalerrors == 1)
				{
					(void) odbx_finish(db);
					return EX_DATAERR;
				}

				continue;
			}

			skipsigs = 0;

			/* get, or create, the reporter ID if needed */
			if (strcasecmp(reporter, fields[1]) != 0)
			{
				(void) sanitize(db, fields[1], safesql,
				                sizeof safesql);

				snprintf(sql, sizeof sql,
				         "SELECT id FROM reporters WHERE name = '%s'",
				         safesql);

				repid = sql_get_int(db, sql);
				if (repid == -1)
				{
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
				else if (repid == 0)
				{
					if (norepadd == 1)
					{
						fprintf(stderr,
						        "%s: no such reporter '%s' at line %d\n",
						        progname, fields[1],
						        line);

						skipsigs = 1;

						continue;
					}

					snprintf(sql, sizeof sql,
					         "INSERT INTO reporters (name) VALUES ('%s')",
					         safesql);

					repid = sql_do(db, sql);
					if (repid == -1)
					{
						(void) odbx_finish(db);
						return EX_SOFTWARE;
					}

					snprintf(sql, sizeof sql,
					         "SELECT %s", lastrow);

					repid = sql_get_int(db, sql);
					if (repid == -1)
					{
						(void) odbx_finish(db);
						return EX_SOFTWARE;
					}
					else if (repid == 0)
					{
						fprintf(stderr,
						        "%s: failed to create reporter record for '%s'\n",
						        progname,
						        fields[1]);
						(void) odbx_finish(db);
						return EX_SOFTWARE;
					}
				}

				strlcpy(reporter, fields[1], sizeof reporter);
			}

			/* get, or create, the domain ID if needed */
			(void) sanitize(db, fields[2], safesql,
			                sizeof safesql);

			snprintf(sql, sizeof sql,
			         "SELECT id FROM domains WHERE name = '%s'",
			         safesql);

			domid = sql_get_int(db, sql);
			if (domid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
			else if (domid == 0)
			{
				snprintf(sql, sizeof sql,
				         "INSERT INTO domains (name) VALUES ('%s')",
				         safesql);

				domid = sql_do(db, sql);
				if (domid == -1)
				{
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}

				snprintf(sql, sizeof sql,
				         "SELECT %s", lastrow);

				domid = sql_get_int(db, sql);
				if (domid == -1)
				{
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
				else if (domid == 0)
				{
					fprintf(stderr,
					        "%s: failed to create domain record for '%s'\n",
					        progname, fields[2]);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
			}

			/* get, or create, the IP address ID if needed */
			(void) sanitize(db, fields[3], safesql,
			                sizeof safesql);

			snprintf(sql, sizeof sql,
			         "SELECT id FROM ipaddrs WHERE addr = '%s'",
			         safesql);

			addrid = sql_get_int(db, sql);
			if (addrid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
			else if (addrid == 0)
			{
				snprintf(sql, sizeof sql,
				         "INSERT INTO ipaddrs (addr) VALUES ('%s')",
				         safesql);

				addrid = sql_do(db, sql);
				if (addrid == -1)
				{
					/* repeat the get */
					snprintf(sql, sizeof sql,
					         "SELECT id FROM ipaddrs WHERE addr = '%s'",
					         safesql);

					addrid = sql_get_int(db, sql);
					if (addrid == -1)
					{
						(void) odbx_finish(db);
						return EX_SOFTWARE;
					}
				}
				else
				{
					snprintf(sql, sizeof sql,
					         "SELECT %s", lastrow);

					addrid = sql_get_int(db, sql);
					if (addrid == -1)
					{
						(void) odbx_finish(db);
						return EX_SOFTWARE;
					}
					else if (addrid == 0)
					{
						fprintf(stderr,
						        "%s: failed to create IP address record for '%s'\n",
						        progname, fields[3]);
						(void) odbx_finish(db);
						return EX_SOFTWARE;
					}
				}
			}

			/* verify data safety */
			if (sanitize(db, fields[0], safesql, sizeof safesql) ||
			    sanitize(db, fields[4], safesql, sizeof safesql) ||
			    sanitize(db, fields[5], safesql, sizeof safesql) ||
			    sanitize(db, fields[6], safesql, sizeof safesql) ||
			    sanitize(db, fields[7], safesql, sizeof safesql) ||
			    sanitize(db, fields[8], safesql, sizeof safesql))
			{
				fprintf(stderr,
				        "%s: unsafe data at input line %d\n",
				        progname, line);

				skipsigs = 1;

				continue;
			}

			/* see if this is a duplicate */
			(void) sql_mktime(fields[4], timebuf, sizeof timebuf);
			snprintf(sql, sizeof sql,
			         "SELECT id FROM messages WHERE jobid = '%s' AND reporter = %d AND msgtime = '%s'",
			         fields[0], repid, timebuf);

			msgid = sql_get_int(db, sql);
			if (msgid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
			else if (msgid != 0)
			{
				if (dontskip == 0)
				{
					fprintf(stderr,
					        "%s: skipping duplicate message at line %d\n",
					        progname, line);
					skipsigs = 1;
				}

				continue;
			}

			(void) sql_mktime(fields[4], timebuf, sizeof timebuf);
			snprintf(sql, sizeof sql,
			         "INSERT INTO messages (jobid, reporter, from_domain, ip, msgtime, size, sigcount, atps, spam) VALUES ('%s', %d, %d, %d, '%s', %s, %s, %s, %s)",
			         fields[0],	/* jobid */
			         repid,		/* reporter */
			         domid,		/* from_domain */
			         addrid,	/* ip */
			         timebuf,	/* msgtime */
			         fields[5],	/* size */
			         fields[6],	/* sigcount */
			         fields[7],	/* atps */
			         fields[8]);	/* spam */

			msgid = sql_do(db, sql);
			if (msgid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}

			/* get back the message ID */
			snprintf(sql, sizeof sql, "SELECT %s", lastrow);

			msgid = sql_get_int(db, sql);
			if (msgid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
			else if (msgid == 0)
			{
				fprintf(stderr,
				        "%s: failed to create message record for '%s'\n",
				        progname, fields[0]);
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
		}

		/* processing section for signatures */
		else if (c == 'S')
		{
			if (inversion != DKIMS_VERSION)
			{
				fprintf(stderr,
				        "%s: ignoring old format at input line %d\n",
				        progname, line);

				continue;
			}

			if (n != DKIMS_SI_MAX + 1)
			{
				fprintf(stderr,
				        "%s: unexpected signature field count (%d) at input line %d\n",
				        progname, n, line);
				continue;
			}
			else if (msgid <= 0)
			{
				fprintf(stderr,
				        "%s: signature record before message record at input line %d\n",
				        progname, line);
				continue;
			}
			else if (skipsigs == 1)
			{
				continue;
			}

			/* get, or create, the domain ID if needed */
			(void) sanitize(db, fields[0], safesql,
			                sizeof safesql);

			snprintf(sql, sizeof sql,
			         "SELECT id FROM domains WHERE name = '%s'",
			         safesql);

			domid = sql_get_int(db, sql);
			if (domid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
			else if (domid == 0)
			{
				snprintf(sql, sizeof sql,
				         "INSERT INTO domains (name) VALUES ('%s')",
				         safesql);

				domid = sql_do(db, sql);
				if (domid == -1)
				{
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}

				snprintf(sql, sizeof sql, "SELECT %s",
				         lastrow);

				domid = sql_get_int(db, sql);
				if (domid == -1)
				{
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
				else if (domid == 0)
				{
					fprintf(stderr,
					        "%s: failed to create domain record for '%s'\n",
					        progname, fields[0]);
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
			}

			if (sanitize(db, fields[1], safesql, sizeof safesql) ||
			    sanitize(db, fields[2], safesql, sizeof safesql) ||
			    sanitize(db, fields[3], safesql, sizeof safesql) ||
			    sanitize(db, fields[4], safesql, sizeof safesql) ||
			    sanitize(db, fields[5], safesql, sizeof safesql))
			{
				fprintf(stderr,
				        "%s: unsafe data at input line %d\n",
				        progname, line);
				continue;
			}

			snprintf(sql, sizeof sql,
			         "INSERT INTO signatures (message, domain, pass, fail_body, siglength, sigerror, dnssec) VALUES (%d, %d, %s, %s, %s, %s, %s)",
			         msgid,		/* message */
			         domid,		/* domain */
			         fields[1],	/* pass */
			         fields[2],	/* fail_body */
			         fields[3],	/* siglength */
			         fields[4],	/* sigerror */
			         fields[5]);	/* dnssec */

			sigid = sql_do(db, sql);
			if (sigid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}

			/* get back the signature ID */
			snprintf(sql, sizeof sql, "SELECT %s", lastrow);

			sigid = sql_get_int(db, sql);
			if (sigid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
			else if (sigid == 0)
			{
				fprintf(stderr,
				        "%s: failed to create signature record for input line %d\n",
				        progname, line);
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
		}

		/* processing section for message status updates */
		else if (c == 'U' && inversion == DKIMS_VERSION)
		{
			if (n != 4)
			{
				fprintf(stderr,
				        "%s: unexpected update field count (%d) at input line %d\n",
				        progname, n, line);

				if (showfields == 1)
					dumpfields(stderr, fields, n);

				continue;
			}

			/* get the reporter ID */
			if (strcasecmp(reporter, fields[1]) != 0)
			{
				(void) sanitize(db, fields[1], safesql,
				                sizeof safesql);

				snprintf(sql, sizeof sql,
				         "SELECT id FROM reporters WHERE name = '%s'",
				         safesql);

				repid = sql_get_int(db, sql);
				if (repid == -1)
				{
					(void) odbx_finish(db);
					return EX_SOFTWARE;
				}
				else if (repid == 0)
				{
					if (norepadd == 1)
					{
						fprintf(stderr,
						        "%s: no such reporter '%s' at line %d\n",
						        progname, fields[1],
						        line);
					}

					continue;
				}

				strlcpy(reporter, fields[1], sizeof reporter);
			}

			/* verify data safety */
			if (sanitize(db, fields[0], safesql, sizeof safesql) ||
			    sanitize(db, fields[2], safesql, sizeof safesql) ||
			    sanitize(db, fields[3], safesql, sizeof safesql))
			{
				fprintf(stderr,
				        "%s: unsafe data at input line %d\n",
				        progname, line);

				continue;
			}

			/* get the message ID */
			if (strcmp(fields[2], "0") == 0)
			{
				snprintf(sql, sizeof sql,
				         "SELECT MAX(id) FROM messages WHERE jobid = '%s' AND reporter = %d",
				         fields[0], repid);
			}
			else
			{
				(void) sql_mktime(fields[2], timebuf,
				                  sizeof timebuf);
				snprintf(sql, sizeof sql,
				         "SELECT id FROM messages WHERE jobid = '%s' AND reporter = %d AND msgtime = '%s'",
				         fields[0], repid, timebuf);
			}

			msgid = sql_get_int(db, sql);
			if (msgid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
			else if (msgid == 0)
			{
				fprintf(stderr,
				        "%s: unknown message for update at line %d\n",
				        progname, line);
				continue;
			}

			snprintf(sql, sizeof sql,
			         "UPDATE messages SET spam = %s WHERE id = %d",
			         fields[3],	/* spam */
			         msgid);	/* message ID */

			msgid = sql_do(db, sql);
			if (msgid == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
		}

#ifdef _FFR_STATSEXT
		/* processing section for extensions */
		else if (c == 'X')
		{
			if (inversion != DKIMS_VERSION)
			{
				fprintf(stderr,
				        "%s: ignoring old format at input line %d\n",
				        progname, line);

				continue;
			}

			if (n != 2)
			{
				fprintf(stderr,
				        "%s: unexpected extension field count (%d) at input line %d\n",
				        progname, n, line);

				if (showfields == 1)
					dumpfields(stderr, fields, n);

				continue;
			}
			else if (msgid <= 0)
			{
				fprintf(stderr,
				        "%s: extension record before message record at input line %d\n",
				        progname, line);
				continue;
			}
			else if (skipsigs == 1 || extensions == 0)
			{
				continue;
			}

			if (sanitize(db, fields[0], safesql, sizeof safesql) ||
			    sanitize(db, fields[1], safesql, sizeof safesql))
			{
				fprintf(stderr,
				        "%s: unsafe data at input line %d\n",
				        progname, line);
				continue;
			}

			snprintf(sql, sizeof sql,
			         "UPDATE messages SET %s = %s WHERE id = %d",
			         fields[0], fields[1], msgid);

			err = sql_do(db, sql);
			if (err == -1)
			{
				(void) odbx_finish(db);
				return EX_SOFTWARE;
			}
		}
#endif /* _FFR_STATSEXT */

		/* unknown record type */
		else
		{
			fprintf(stderr,
			        "%s: unknown record type '%c' at input line %d\n",
			        progname, c, line);

			if (fatalerrors == 1)
			{
				(void) odbx_finish(db);
				return EX_DATAERR;
			}
		}
	}

	if (fields != NULL)
		free(fields);

	if (ferror(stdin))
	{
		fprintf(stderr, "%s: fgets(): %s\n", progname,
		        strerror(errno));
		(void) odbx_finish(db);
		return EX_OSERR;
	}

	/* unbind */
	err = odbx_unbind(db);
	if (err < 0)
	{
		fprintf(stderr, "%s: odbx_unbind(): %s\n", progname,
		        odbx_error(db, err));
		(void) odbx_finish(db);
		return EX_SOFTWARE;
	}

	/* shut down */
	if (odbx_finish(db) < 0)
	{
		fprintf(stderr, "%s: odbx_finish() failed\n", progname);
		return EX_SOFTWARE;
	}

	return EX_OK;
}
