/*
**  Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dr_test00_c_id[] = "@(#)$Id: t-test124.c,v 1.2 2009/12/08 19:14:27 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/select.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libdkimrep includes */
#include "dkim-rep.h"

#define	DKIM_REP_ROOT	"al.dkim-reputation.org"
#define	TESTDOMAIN	"freelotto.com"

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
	int rep;
	DKIM_REP dr;
	void *qh = NULL;
	DKIM_REP_STAT status;
	struct timeval timeout;

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	printf("*** checking reputation for \"%s\"\n", TESTDOMAIN);

	dr = dkim_rep_init(NULL, NULL, NULL);
	assert(dr != NULL);

	dkim_rep_setdomain(dr, DKIM_REP_ROOT);

	status = dkim_rep_query_start(dr, "user", TESTDOMAIN,
	                              TESTDOMAIN, &qh);
	assert(status == DKIM_REP_DNS_SUCCESS);
	assert(qh != NULL);

	timeout.tv_sec = 5;
	timeout.tv_usec = 5;

	rep = 0;
	status = dkim_rep_query_check(dr, qh, &timeout, &rep);
	assert(status == DKIM_REP_DNS_SUCCESS);

	printf("--- \"%s\" reputation %d\n", TESTDOMAIN, rep);

	dkim_rep_close(dr);

	return 0;
}
