/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_cleanup_c_id[] = "@(#)$Id: t-cleanup.c,v 1.3 2010/09/02 05:10:57 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "t-testdata.h"

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
	/* needed for code coverage test descriptions */
	printf("*** test cleanup\n");

	assert(unlink(KEYFILE) == 0);

	return 0;
}
