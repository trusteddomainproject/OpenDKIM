/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-testadsp.c,v 1.5 2009/07/23 22:38:37 cm-msk Exp $
*/

#ifndef lint
static char opendkim_testadsp_c[] = "@(#)$Id: opendkim-testadsp.c,v 1.5 2009/07/23 22:38:37 cm-msk Exp $";
#endif /* !lint */

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
#define	CMDLINEOPTS	"d:"
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
	fprintf(stderr,
	        "%s: usage: %s domain [...]\n",
	        progname, progname);

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
