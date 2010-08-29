/*
**  Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-stats.c,v 1.13.2.7 2010/08/29 20:27:29 cm-msk Exp $
*/

#ifndef lint
static char opendkim_stats_c_id[] = "$Id: opendkim-stats.c,v 1.13.2.7 2010/08/29 20:27:29 cm-msk Exp $";
#endif /* ! lint */

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

/* libopendkim includes */
#include <dkim.h>

/* macros, definitions */
#define	MAXLINE		2048

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

		/* processing section for messages */
		if (c == 'M')
		{
			time_t rtime;
			char *adsp;
			char *adsppf;
			char *ct;
			char *cte;

			if (n != 16)
			{
				fprintf(stderr,
				        "%s: unexpected field count at input line %d\n",
				        progname, line);
				continue;
			}

			/* format the data */
			rtime = (time_t) atoi(fields[5]);
			adsp = "not found";
			adsppf = "passed";
			if (fields[7][0] == '1')
			{
				adsp = "invalid";

				if (fields[8][0] == '1')
					adsp = "unknown";
				else if (fields[9][0] == '1')
					adsp = "all";
				else if (fields[10][0] == '1')
					adsp = "discardable";

				if (fields[11][0] == '1')
					adsppf = "failed";
			}

			if (fields[14][0] == '\0')
				ct = "(default)";
			else
				ct = fields[14];

			if (fields[15][0] == '\0')
				cte = "(default)";
			else
				cte = fields[15];

			if (ms > 0)
			{
				fprintf(stdout, "\n");
				ms = 0;
			}

			fprintf(stdout, "Job %s at %s (size %s)\n\treceived via %s at %s\tfrom domain = `%s', %s Received header fields\n\tContent type %s, content transfer encoding %s\n\t%s to come from a mailing list\n\tADSP %s (%s)\n",
			        fields[0], fields[1], fields[6], fields[3],
			        ctime(&rtime), fields[2], fields[13],
			        ct, cte,
			        fields[12][0] == '0' ? "Does not appear"
			                             : "Appears",
			        adsp, adsppf);

			m++;
		}

		/* processing section for signatures */
		else if (c == 'S')
		{
			char *sigstat;
			char *alg;
			char *hc;
			char *bc;
			char *siglen;
			char *dnssec;

			if (n != 19)
			{
				fprintf(stderr,
				        "%s: unexpected field count at input line %d\n",
				        progname, line);
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
			if (fields[5][0] == '1')
				sigstat = "PASSED";
			else if (fields[6][0] == '1')
				sigstat = "FAILED (body changed)";
			else if (fields[4][0] == '1')
				sigstat = "IGNORED";
			else if (atoi(fields[12]) == DKIM_SIGERROR_KEYREVOKED)
				sigstat = "REVOKED";
			else if (fields[12][0] != '0')
				sigstat = "ERROR (syntax error in signature)";
			else
				sigstat = "UNKNOWN";

			alg = "rsa-sha1";
			if (fields[1][0] == '1')
				alg = "rsa-sha256";

			hc = "simple";
			if (fields[2][0] == '1')
				hc = "relaxed";

			bc = "simple";
			if (fields[3][0] == '1')
				bc = "relaxed";

			if (fields[7][0] == '-')
				siglen = "(whole message)";
			else
				siglen = fields[7];

			switch (fields[16][0])
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

			syntax = atoi(fields[12]);
			syntax = (syntax == DKIM_SIGERROR_VERSION ||
			          syntax == DKIM_SIGERROR_DOMAIN ||
			          syntax == DKIM_SIGERROR_TIMESTAMPS ||
			          syntax == DKIM_SIGERROR_MISSING_C ||
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

			fprintf(stdout, "\tSignature %d from %s\n\t\talgorithm %s\n\t\theader canonicalization %s, body canonicalization %s\n\t\t%s\n\t\tsigned bytes: %s\n\t\tSignature properties: %s %s %s %s\n\t\tKey properties: %s %s %s %s %s %s\n\t\tDNSSEC status: %s\n\t\tSigned fields: %s\n\t\tChanged fields: %s\n",
			        ms, fields[0], alg, hc, bc, sigstat, siglen,
			        fields[13][0] == '1' ? "t=" : "",
			        atoi(fields[12]) == DKIM_SIGERROR_FUTURE ? "t=future"
				                                         : "",
			        fields[14][0] == '1' ? "x=" : "",
			        fields[15][0] == '1' ? "z=" : "",
			        fields[8][0] == '1' ? "t=" : "",
			        fields[9][0] == '1' ? "g=" : "",
			        fields[10][0] == '1' ? "g=name" : "",
			        syntax != 0 ? "syntax" : "",
			        atoi(fields[12]) == DKIM_SIGERROR_NOKEY ? "NXDOMAIN" : "",
			        fields[11][0] == '1' ? "DK" : "",
			        dnssec,
			        fields[17], fields[18]);

			s++;
		}

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
