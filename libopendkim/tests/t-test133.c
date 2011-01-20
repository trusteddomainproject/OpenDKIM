/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_test133_c_id[] = "@(#)$Id: t-test133.c,v 1.2 2010/03/03 02:58:05 grooverdan Exp $";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"

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
	unsigned long libversion;

	printf("*** testing dkim_libversion()\n");

	libversion = dkim_libversion();
	assert(libversion == OPENDKIM_LIB_VERSION);

	return 0;
}
