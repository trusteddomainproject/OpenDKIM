/*
**  Copyright (c) 2011, 2012, The OpenDKIM Project.  All rights reserved.
*/

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

#define	TESTDOMAIN	"example.com"
#define	TESTUSER1	"good"
#define	TESTUSER2	"bad"

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

	printf("*** basic reputation checks\n");

	dr = dkim_rep_init(NULL, NULL, NULL);
	assert(dr != NULL);

	status = dkim_rep_query_start(dr, TESTUSER1, TESTDOMAIN,
	                              TESTDOMAIN, &qh);
	assert(status == DKIM_REP_DNS_SUCCESS);
	assert(qh != NULL);

	timeout.tv_sec = 5;
	timeout.tv_usec = 5;

	rep = 0;
	status = dkim_rep_query_check(dr, qh, &timeout, &rep);
	assert(status == DKIM_REP_STAT_FOUND);

	printf("--- %s@%s d=%s reputation %d\n", TESTUSER1, TESTDOMAIN,
	       TESTDOMAIN, rep);

	status = dkim_rep_query_start(dr, TESTUSER2, TESTDOMAIN,
	                              TESTDOMAIN, &qh);
	assert(status == DKIM_REP_DNS_SUCCESS);
	assert(qh != NULL);

	timeout.tv_sec = 5;
	timeout.tv_usec = 5;

	rep = 0;
	status = dkim_rep_query_check(dr, qh, &timeout, &rep);
	assert(status == DKIM_REP_STAT_FOUND);

	printf("--- %s@%s d=%s reputation %d\n", TESTUSER2, TESTDOMAIN,
	       TESTDOMAIN, rep);

	dkim_rep_close(dr);

	return 0;
}
