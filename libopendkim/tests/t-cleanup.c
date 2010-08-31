/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_cleanup_c_id[] = "@(#)$Id: t-cleanup.c,v 1.2 2010/08/31 13:50:12 grooverdan Exp $";
#endif /* !lint */

/* system includes */
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

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
