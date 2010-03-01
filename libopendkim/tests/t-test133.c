/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_test133_c_id[] = "@(#)$Id: t-test133.c,v 1.1 2010/03/01 19:15:38 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <assert.h>

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
