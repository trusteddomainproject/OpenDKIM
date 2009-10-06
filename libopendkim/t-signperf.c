/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_signperf_c_id[] = "@(#)$Id: t-signperf.c,v 1.4 2009/10/06 17:36:10 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sysexits.h>

/* libopendkim includes */
#include "dkim.h"
#include "dkim-tables.h"
#include "t-testdata.h"

#define	DEFMSGSIZE	1024
#define	DEFTESTINT	5
#define	BODYBUFRSZ	8192
#define	MAXHEADER	4096

char *progname;

/*
**  USAGE -- print usage message
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
	        "\t-b bodycanon\tbody canonicalization to use\n"
	        "\t-h hdrcanon \theader canonicalization to use\n"
	        "\t-m bytes    \tmessage size in bytes\n"
	        "\t-s signalg  \tsigning algorithm to use\n"
	        "\t-t seconds  \ttest time in seconds\n",
	        progname, progname);

	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	The usual.
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	DKIM_STAT status;
	u_int signcnt = 0;
	int c;
	int w;
	int rate;
	size_t msgsize = DEFMSGSIZE;
	size_t msgrem;
	size_t wsz;
	char *p;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];
	unsigned char body[BODYBUFRSZ];
	time_t start = DEFTESTINT;
	time_t testint = DEFTESTINT;
	dkim_canon_t hcanon = DKIM_CANON_RELAXED;
	dkim_canon_t bcanon = DKIM_CANON_SIMPLE;
#ifdef DKIM_SIGN_RSASHA256
	dkim_alg_t signalg = DKIM_SIGN_RSASHA256;
#else /* DKIM_SIGN_RSASHA256 */
	dkim_alg_t signalg = DKIM_SIGN_RSASHA1;
#endif /* DKIM_SIGN_RSASHA256 */

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, "b:h:m:s:t:")) != -1)
	{
		switch (c)
		{
		  case 'b':
			bcanon = dkim_name_to_code(canonicalizations, optarg);
			if (bcanon == (dkim_canon_t) -1)
			{
				fprintf(stderr,
				        "%s: unknown canonicalization `%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 'h':
			hcanon = dkim_name_to_code(canonicalizations, optarg);
			if (hcanon == (dkim_canon_t) -1)
			{
				fprintf(stderr,
				        "%s: unknown canonicalization `%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 'm':
			msgsize = strtoul(optarg, &p, 10);
			if (*p != '\0')
			{
				fprintf(stderr, "%s: invalid size `%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 's':
			signalg = dkim_name_to_code(algorithms, optarg);
			if (signalg == (dkim_alg_t) -1)
			{
				fprintf(stderr,
				        "%s: unknown signing algorithm `%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 't':
			testint = strtoul(optarg, &p, 10);
			if (*p != '\0')
			{
				fprintf(stderr, "%s: invalid seconds `%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;


		  default:
			return usage();
		}
	}

	fprintf(stdout,
	        "*** SIGNING SPEED TEST: %s/%s with %s, size %u for %lds\n",
	        dkim_code_to_name(canonicalizations, hcanon),
	        dkim_code_to_name(canonicalizations, bcanon),
	        dkim_code_to_name(algorithms, signalg),
	        msgsize, (long) testint);

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);

	key = KEY;

	srandom(time(NULL));

	/* prepare a random body buffer */
	for (c = 0, w = 0; c < sizeof body; c++)
	{
		if (w >= 75 && c < sizeof body - 2)
		{
			body[c++] = '\r';
			body[c++] = '\n';
			w = 0;
		}

		body[c++] = (random() + 32) % 127;
		w++;
	}

	(void) time(&start);

	while (time(NULL) < start + testint)
	{
		dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
		                 hcanon, bcanon, signalg, -1L, &status);

		status = dkim_header(dkim, HEADER02, strlen(HEADER02));

		status = dkim_header(dkim, HEADER03, strlen(HEADER03));

		status = dkim_header(dkim, HEADER04, strlen(HEADER04));

		status = dkim_header(dkim, HEADER05, strlen(HEADER05));

		status = dkim_header(dkim, HEADER06, strlen(HEADER06));

		status = dkim_header(dkim, HEADER07, strlen(HEADER07));

		status = dkim_header(dkim, HEADER08, strlen(HEADER08));

		status = dkim_header(dkim, HEADER09, strlen(HEADER09));

		status = dkim_eoh(dkim);

		msgrem = msgsize;

		while (msgrem > 0)
		{
			wsz = MIN(msgrem, sizeof body);

			status = dkim_body(dkim, body, wsz);

			msgrem -= wsz;
		}

		status = dkim_eom(dkim, NULL);

		memset(hdr, '\0', sizeof hdr);
		status = dkim_getsighdr(dkim, hdr, sizeof hdr,
		                        strlen(DKIM_SIGNHEADER) + 2);

		status = dkim_free(dkim);

		signcnt++;
	}

	dkim_close(lib);

	rate = signcnt / testint;

	fprintf(stdout, "*** %u messages signed (%d msgs/sec)\n",
	        signcnt, rate);

	return 0;
}
