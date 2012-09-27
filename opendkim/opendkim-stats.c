/*
**  Copyright (c) 2010-2012, The Trusted Domain Project.  All rights reserved.
**
*/

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sysexits.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

/* OpenDKIM includes */
#include "build-config.h"
#include "stats.h"

/* libopendkim includes */
#include <dkim.h>

/* macros, definitions */
#define	MAXLINE		2048

#ifndef MAX
# define MAX(x,y)	((x) > (y) ? (x) : (y))
#endif /* ! MAX */

/* globals */
char *progname;

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
	fprintf(stderr, "%s: usage: %s [statsfile]\n", progname, progname);

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
	int m = 0;
	int s = 0;
	int ms = 0;
	int nfields = 0;
	int line;
	int syntax = 0;
	char *p;
	char *infile = NULL;
	char **fields = NULL;
	FILE *in;
	char buf[MAXLINE + 1];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	if (argc == 2)
		infile = argv[1];
	else if (argc != 1)
		return usage();

	if (infile != NULL)
	{
		in = fopen(infile, "r");
		if (in == NULL)
		{
			fprintf(stderr, "%s: %s: fopen(): %s\n", progname,
			        infile, strerror(errno));
			return EX_UNAVAILABLE;
		}
	}
	else
	{
		in = stdin;
	}

	/* initialize stuff */
	memset(buf, '\0', sizeof buf);
	line = 0;

	/* read lines from stdin */
	while (fgets(buf, sizeof buf - 1, in) != NULL)
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
					return EX_OSERR;
				}

				nfields = newnf;
				fields = new;
			}

			fields[n++] = p;
		}

		/* processing section for version tags */
		if (c == 'V')
		{
			int inversion;

			if (n != 1)
			{
				fprintf(stderr,
				        "%s: unexpected version field count (%d) at input line %d\n",
				        progname, n, line);

				continue;
			}

			inversion = atoi(fields[0]);
			if (inversion != DKIMS_VERSION)
			{
				fprintf(stderr,
				        "%s: unknown version (%d) at input line %d\n",
				        progname, inversion, line);

				continue;
			}
		}

		/* processing section for messages */
		else if (c == 'M')
		{
			time_t rtime;
#ifdef _FFR_ATPS
			char *atps;
#endif /* _FFR_ATPS */
#ifdef _FFR_REPUTATION
			char *spam;
#endif /* _FFR_REPUTATION */

			if (n != DKIMS_MI_MAX + 1)
			{
				fprintf(stderr,
				        "%s: unexpected message field count (%d) at input line %d\n",
				        progname, n, line);
				continue;
			}

			/* format the data */
			rtime = (time_t) atoi(fields[DKIMS_MI_MSGTIME]);

#ifdef _FFR_ATPS
			atps = "not checked";

			if (fields[DKIMS_MI_ATPS][0] == '0')
				atps = "no match";
			else if (fields[DKIMS_MI_ATPS][0] == '1')
				atps = "match";
#endif /* _FFR_ATPS */

#ifdef _FFR_REPUTATION
			spam = "unknown";

			if (fields[DKIMS_MI_SPAM][0] == '0')
				spam = "not spam";
			else if (fields[DKIMS_MI_SPAM][0] == '1')
				spam = "spam";
#endif /* _FFR_REPUTATION */

			if (ms > 0)
			{
				fprintf(stdout, "\n");
				ms = 0;
			}

			fprintf(stdout, "Job %s at %s (size %s)\n\treceived via %s at %s\tfrom domain = '%s'\n",
			        fields[DKIMS_MI_JOBID],
			        fields[DKIMS_MI_REPORTER],
			        fields[DKIMS_MI_MSGLEN],
			        fields[DKIMS_MI_IPADDR],
			        ctime(&rtime),
			        fields[DKIMS_MI_FROMDOMAIN]);

#ifdef _FFR_ATPS
			fprintf(stdout, "\tATPS %s\n", atps);
#endif /* _FFR_ATPS */

#ifdef _FFR_REPUTATION
			fprintf(stdout, "\tSpam: %s\n", spam);
#endif /* _FFR_REPUTATION */

			m++;
		}

		/* processing section for signatures */
		else if (c == 'S')
		{
			char *sigstat;
			char *siglen;
			char *dnssec;

			if (n != DKIMS_SI_MAX + 1)
			{
				fprintf(stderr,
				        "%s: unexpected signature field count (%d) at input line %d\n",
				        progname, n, line);
				continue;
			}
			else if (m == 0)
			{
				fprintf(stderr,
				        "%s: signature record before message record at input line %d\n",
				        progname, line);
				continue;
			}

			ms++;

			/* format output */
			if (fields[DKIMS_SI_PASS][0] == '1')
				sigstat = "PASSED";
			else if (fields[DKIMS_SI_FAIL_BODY][0] == '1')
				sigstat = "FAILED (body changed)";
			else if (atoi(fields[DKIMS_SI_SIGERROR]) == DKIM_SIGERROR_KEYREVOKED)
				sigstat = "REVOKED";
			else if (fields[DKIMS_SI_SIGERROR][0] != '0')
				sigstat = "ERROR";
			else
				sigstat = "UNKNOWN";

			if (fields[DKIMS_SI_SIGLENGTH][0] == '-')
				siglen = "(whole message)";
			else
				siglen = fields[DKIMS_SI_SIGLENGTH];

			switch (fields[DKIMS_SI_DNSSEC][0])
			{
			  case '-':
				dnssec = "UNKNOWN";
				break;

			  case '0':
				dnssec = "BOGUS";
				break;

			  case '1':
				dnssec = "INSECURE";
				break;

			  case '2':
				dnssec = "SECURE";
				break;
			}

			syntax = atoi(fields[DKIMS_SI_SIGERROR]);
			syntax = (syntax == DKIM_SIGERROR_VERSION ||
			          syntax == DKIM_SIGERROR_DOMAIN ||
			          syntax == DKIM_SIGERROR_TIMESTAMPS ||
			          syntax == DKIM_SIGERROR_INVALID_HC ||
			          syntax == DKIM_SIGERROR_INVALID_BC ||
			          syntax == DKIM_SIGERROR_MISSING_A ||
			          syntax == DKIM_SIGERROR_INVALID_A ||
			          syntax == DKIM_SIGERROR_MISSING_H ||
			          syntax == DKIM_SIGERROR_INVALID_L ||
			          syntax == DKIM_SIGERROR_INVALID_Q ||
			          syntax == DKIM_SIGERROR_INVALID_QO ||
			          syntax == DKIM_SIGERROR_MISSING_D ||
			          syntax == DKIM_SIGERROR_EMPTY_D ||
			          syntax == DKIM_SIGERROR_MISSING_S ||
			          syntax == DKIM_SIGERROR_EMPTY_S ||
			          syntax == DKIM_SIGERROR_MISSING_B ||
			          syntax == DKIM_SIGERROR_EMPTY_B ||
			          syntax == DKIM_SIGERROR_CORRUPT_B ||
			          syntax == DKIM_SIGERROR_MISSING_BH ||
			          syntax == DKIM_SIGERROR_EMPTY_BH ||
			          syntax == DKIM_SIGERROR_CORRUPT_BH ||
			          syntax == DKIM_SIGERROR_EMPTY_H ||
			          syntax == DKIM_SIGERROR_INVALID_H ||
			          syntax == DKIM_SIGERROR_TOOLARGE_L ||
			          syntax == DKIM_SIGERROR_MBSFAILED);

			fprintf(stdout, "\tSignature %d from %s\n\t\t%s\n\t\tsigned bytes: %s\n\t\tSignature properties: %s\n\t\tKey properties: %s %s\n\t\tDNSSEC status: %s\n",
			        ms,
			        fields[DKIMS_SI_DOMAIN],
			        sigstat, siglen,
			        atoi(fields[DKIMS_SI_SIGERROR]) == DKIM_SIGERROR_FUTURE ? "t=future"
				                                                        : "",
			        syntax != 0 ? "syntax" : "",
			        atoi(fields[DKIMS_SI_SIGERROR]) == DKIM_SIGERROR_NOKEY ? "NXDOMAIN"
			                                                               : "",
			        dnssec);

			s++;
		}

#ifdef _FFR_STATSEXT
		/* processing section for extension data */
		else if (c == 'X')
		{
			fprintf(stdout, "\tExtension data: %s=%s\n",
			        fields[0], fields[1]);
		}
#endif /* _FFR_STATSEXT */
 
		/* unknown record type */
		else
		{
			fprintf(stderr,
			        "%s: unknown record type '%c' at input line %d\n",
			        progname, c, line);
		}
	}

	if (ferror(in))
	{
		fprintf(stderr, "%s: fgets(): %s at input line %d\n", progname,
		        strerror(errno), line);
	}

	if (infile != NULL)
		fclose(in);

	fprintf(stdout, "%s: %d message%s, %d signature%s processed\n",
	        progname, m, m == 0 ? "" : "s", s, s == 0 ? "" : "s");

	return EX_OK;
}
