/*
**  Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dr_test00_c_id[] = "@(#)$Id: t-test124.c,v 1.2 2009/12/08 19:14:27 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libdkimrep includes */
#include "dkim-rep.h"

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
#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	FINISH ME
}
