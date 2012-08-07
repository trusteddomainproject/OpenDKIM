/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2010-2012, The Trusted Domain Project.  All rights reserved.
*/

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
