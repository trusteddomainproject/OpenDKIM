/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sysexits.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "../dkim-tables.h"
#include "t-testdata.h"

#define	DEFMSGSIZE	1024
#define	DEFTESTINT	5
#define	BODYBUFRSZ	8192
#define	MAXHEADER	4096

#ifndef MIN
# define MIN(x,y)	((x) < (y) ? (x) : (y))
#endif /* ! MIN */

char *progname;

/*
**  CANON_CODE -- convert a canonicalization name to its code
**
**  Parameters:
**  	name -- name to convert
**
**  Return value:
**  	dkim_canon_t
*/

dkim_canon_t
canon_code(char *name)
{
	if (name == NULL)
		return (dkim_canon_t) DKIM_CANON_UNKNOWN;
	else if (strcasecmp(name, "simple") == 0)
		return (dkim_canon_t) DKIM_CANON_SIMPLE;
	else if (strcasecmp(name, "relaxed") == 0)
		return (dkim_canon_t) DKIM_CANON_RELAXED;
	else
		return (dkim_canon_t) DKIM_CANON_UNKNOWN;
}

/*
**  CANON_NAME -- convert a canonicalization code to its name
**
**  Parameters:
**  	code -- code to convert
**
**  Return value:
**  	Pointer to name string.
*/

char *
canon_name(dkim_canon_t code)
{
	switch (code)
	{
	  case DKIM_CANON_SIMPLE:
		return "simple";

	  case DKIM_CANON_RELAXED:
		return "relaxed";

	  case DKIM_CANON_UNKNOWN:
	  default:
		return "unknown";
	}
}

/*
**  ALG_CODE -- convert an algorithm name to its code
**
**  Parameters:
**  	name -- name to convert
**
**  Return value:
**  	dkim_alg_t
*/

dkim_alg_t
alg_code(char *name)
{
	if (name == NULL)
		return (dkim_alg_t) DKIM_SIGN_UNKNOWN;
	else if (strcasecmp(name, "rsa-sha1") == 0)
		return (dkim_alg_t) DKIM_SIGN_RSASHA1;
	else if (strcasecmp(name, "rsa-sha256") == 0)
		return (dkim_alg_t) DKIM_SIGN_RSASHA256;
	else
		return (dkim_alg_t) DKIM_SIGN_UNKNOWN;
}

/*
**  ALG_NAME -- convert an algorithm code to its name
**
**  Parameters:
**  	code -- code to convert
**
**  Return value:
**  	Pointer to name string.
*/

char *
alg_name(dkim_alg_t code)
{
	switch (code)
	{
	  case DKIM_SIGN_DEFAULT:
		return "default";

	  case DKIM_SIGN_RSASHA1:
		return "rsa-sha1";

	  case DKIM_SIGN_RSASHA256:
		return "rsa-sha256";

	  case DKIM_SIGN_UNKNOWN:
	  default:
		return "unknown";
	}
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
	u_int verifycnt = 0;
	int c;
	int w;
	int rate;
	size_t msgsize = DEFMSGSIZE;
	size_t msgrem;
	size_t wsz;
	time_t start = DEFTESTINT;
	time_t testint = DEFTESTINT;
	dkim_canon_t hcanon = DKIM_CANON_RELAXED;
	dkim_canon_t bcanon = DKIM_CANON_SIMPLE;
	dkim_alg_t signalg = DKIM_SIGN_UNKNOWN;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	char *p;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];
	unsigned char body[BODYBUFRSZ];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, "b:h:m:s:t:")) != -1)
	{
		switch (c)
		{
		  case 'b':
			bcanon = canon_code(optarg);
			if (bcanon == (dkim_canon_t) -1)
			{
				fprintf(stderr,
				        "%s: unknown canonicalization '%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 'h':
			hcanon = canon_code(optarg);
			if (hcanon == (dkim_canon_t) -1)
			{
				fprintf(stderr,
				        "%s: unknown canonicalization '%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 'm':
			msgsize = strtoul(optarg, &p, 10);
			if (*p != '\0')
			{
				fprintf(stderr, "%s: invalid size '%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 's':
			signalg = alg_code(optarg);
			if (signalg == (dkim_alg_t) -1)
			{
				fprintf(stderr,
				        "%s: unknown signing algorithm '%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  case 't':
			testint = strtoul(optarg, &p, 10);
			if (*p != '\0')
			{
				fprintf(stderr, "%s: invalid seconds '%s'\n",
				        progname, optarg);
				return EX_USAGE;
			}
			break;

		  default:
			return usage();
		}
	}

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);

	if (signalg == DKIM_SIGN_UNKNOWN)
	{
		if (dkim_libfeature(lib, DKIM_FEATURE_SHA256))
			signalg = DKIM_SIGN_RSASHA256;
		else
			signalg = DKIM_SIGN_RSASHA1;
	}
	else if (signalg == DKIM_SIGN_RSASHA256 &&
	         !dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		fprintf(stdout,
		        "### requested signing algorithm not available\n");
		dkim_close(lib);
		return 1;
	}

	fprintf(stdout,
	        "*** VERIFYING SPEED TEST: %s/%s with %s, size %u for %lds\n",
	        canon_name(hcanon), canon_name(bcanon), alg_name(signalg),
	        (unsigned int) msgsize, (long) testint);

	key = KEY;

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));

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

	/* generate the signature */
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
	snprintf(hdr, sizeof hdr, "%s: ", DKIM_SIGNHEADER);
	status = dkim_getsighdr(dkim, hdr + strlen(hdr),
	                        sizeof hdr - strlen(hdr),
	                        strlen(hdr) + 1);

	status = dkim_free(dkim);

	(void) time(&start);

	/* begin the verify loop */
	while (time(NULL) < start + testint)
	{
		dkim = dkim_verify(lib, JOBID, NULL, &status);

		status = dkim_header(dkim, hdr, strlen(hdr));

		status = dkim_header(dkim, HEADER02, strlen(HEADER02));

		status = dkim_header(dkim, HEADER03, strlen(HEADER03));

		status = dkim_header(dkim, HEADER04, strlen(HEADER04));

		status = dkim_header(dkim, HEADER05, strlen(HEADER05));

		status = dkim_header(dkim, HEADER06, strlen(HEADER06));

		status = dkim_header(dkim, HEADER07, strlen(HEADER07));

		status = dkim_header(dkim, HEADER08, strlen(HEADER08));

		status = dkim_header(dkim, HEADER09, strlen(HEADER09));

		status = dkim_eoh(dkim);

		msgrem = DEFMSGSIZE;

		while (msgrem > 0)
		{
			wsz = MIN(msgrem, sizeof body);

			status = dkim_body(dkim, body, wsz);

			msgrem -= wsz;
		}

		status = dkim_eom(dkim, NULL);

		status = dkim_free(dkim);

		verifycnt++;
	}

	dkim_close(lib);

	rate = verifycnt / testint;

	fprintf(stdout, "*** %u messages verified (%d msgs/sec)\n",
	        verifycnt, rate);

	return 0;
}
