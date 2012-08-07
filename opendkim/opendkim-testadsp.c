/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.
**    All rights reserved.
**
*/

/* system includes */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sysexits.h>
#include <string.h>

/* libopendkim includes */
#include <dkim.h>
#include <dkim-test.h>

/* macros */
#define	BUFRSZ		1024
#define STRORNULL(x)	((x) == NULL ? "(null)" : (x))

/* prototypes */
int usage(void);

/* globals */
char *progname;

/*
**  USAGE -- print a usage message
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_CONFIG
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s domain [...]\n", progname, progname);

	return EX_CONFIG;
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
	DKIM_STAT status;
	int i;
	dkim_policy_t pcode;
	int presult;
	DKIM_LIB *lib;
	char *p;
	const char *domain = NULL;
	char err[BUFRSZ];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
	{
		fprintf(stderr, "%s: dkim_init() failed\n", progname);
		return EX_OSERR;
	}

	if (argc == 1)
		return usage();

	for (i = 1; i < argc; i++)
	{
		domain = argv[i];

		status = dkim_test_adsp(lib, domain, &pcode, &presult,
		                        err, sizeof err);

		if (status != DKIM_STAT_OK)
		{
			fprintf(stderr, "%s: %s: %s\n", progname, domain, err);
		}
		else
		{
			fprintf(stdout,
			        "%s: %s:\n\tpolicy is \"%s\"\n\tpolicy result code is \"%s\"\n",
			        progname, domain,
			        STRORNULL(dkim_getpolicystr(pcode)),
			        STRORNULL(dkim_getpresultstr(presult)));
		}
	}

	(void) dkim_close(lib);

	return EX_OK;
}
