/*
**  Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-stats.c,v 1.19 2010/10/25 20:20:29 cm-msk Exp $
*/

#ifndef lint
static char opendkim_stats_c_id[] = "$Id: opendkim-stats.c,v 1.19 2010/10/25 20:20:29 cm-msk Exp $";
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
#include "stats.h"

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

			if (n != 17)
			{
				fprintf(stderr,
				        "%s: unexpected message field count (%d) at input line %d\n",
				        progname, n, line);
				continue;
			}

			/* format the data */
			rtime = (time_t) atoi(fields[DKIMS_MI_MSGTIME]);
			adsp = "not found";
			adsppf = "passed";
			if (fields[DKIMS_MI_ADSP_FOUND][0] == '1')
			{
				adsp = "invalid";

				if (fields[DKIMS_MI_ADSP_UNKNOWN][0] == '1')
					adsp = "unknown";
				else if (fields[DKIMS_MI_ADSP_ALL][0] == '1')
					adsp = "all";
				else if (fields[DKIMS_MI_ADSP_DISCARD][0] == '1')
					adsp = "discardable";

				if (fields[DKIMS_MI_ADSP_FAIL][0] == '1')
					adsppf = "failed";
			}

			if (fields[DKIMS_MI_CONTENTTYPE][0] == '\0')
				ct = "(default)";
			else
				ct = fields[DKIMS_MI_CONTENTTYPE];

			if (fields[DKIMS_MI_CONTENTENCODING][0] == '\0')
				cte = "(default)";
			else
				cte = fields[DKIMS_MI_CONTENTENCODING];

			if (ms > 0)
			{
				fprintf(stdout, "\n");
				ms = 0;
			}

			fprintf(stdout, "Job %s at %s (size %s)\n\treceived via %s at %s\tfrom domain = `%s', %s Received header fields\n\tContent type %s, content transfer encoding %s\n\t%s to come from a mailing list\n\tADSP %s (%s)\n",
			        fields[DKIMS_MI_JOBID],
			        fields[DKIMS_MI_REPORTER],
			        fields[DKIMS_MI_MSGLEN],
			        fields[DKIMS_MI_IPADDR],
			        ctime(&rtime),
			        fields[DKIMS_MI_FROMDOMAIN],
			        fields[DKIMS_MI_RECEIVEDCNT],
			        ct, cte,
			        fields[DKIMS_MI_MAILINGLIST][0] == '0' ? "Does not appear"
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

#ifdef _FFR_STATS_I
			if (n != 19 && n != 21)
#else /* _FFR_STATS_I */
			if (n != 19)
#endif /* _FFR_STATS_I */
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
			else if (fields[DKIMS_SI_IGNORE][0] == '1')
				sigstat = "IGNORED";
			else if (atoi(fields[DKIMS_SI_SIGERROR]) == DKIM_SIGERROR_KEYREVOKED)
				sigstat = "REVOKED";
			else if (fields[DKIMS_SI_SIGERROR][0] != '0')
				sigstat = "ERROR";
			else
				sigstat = "UNKNOWN";

			alg = "rsa-sha1";
			if (fields[DKIMS_SI_ALGORITHM][0] == '1')
				alg = "rsa-sha256";

			hc = "simple";
			if (fields[DKIMS_SI_HEADER_CANON][0] == '1')
				hc = "relaxed";

			bc = "simple";
			if (fields[DKIMS_SI_BODY_CANON][0] == '1')
				bc = "relaxed";

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
			        ms,
			        fields[DKIMS_SI_DOMAIN],
			        alg, hc, bc, sigstat, siglen,
			        fields[DKIMS_SI_SIG_T][0] == '1' ? "t=" : "",
			        atoi(fields[DKIMS_SI_SIGERROR]) == DKIM_SIGERROR_FUTURE ? "t=future"
				                                                        : "",
			        fields[DKIMS_SI_SIG_X][0] == '1' ? "x=" : "",
			        fields[DKIMS_SI_SIG_Z][0] == '1' ? "z=" : "",
			        fields[DKIMS_SI_KEY_T][0] == '1' ? "t=" : "",
			        fields[DKIMS_SI_KEY_G][0] == '1' ? "g=" : "",
			        fields[DKIMS_SI_KEY_G_NAME][0] == '1' ? "g=name"
			                                              : "",
			        syntax != 0 ? "syntax" : "",
			        atoi(fields[DKIMS_SI_SIGERROR]) == DKIM_SIGERROR_NOKEY ? "NXDOMAIN"
			                                                               : "",
			        fields[DKIMS_SI_KEY_DK_COMPAT][0] == '1' ? "DK"
			                                                 : "",
			        dnssec,
			        fields[DKIMS_SI_SIGNED_FIELDS],
			        fields[DKIMS_SI_CHANGED_FIELDS]);

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
