/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_cleanup_c_id[] = "@(#)$Id: t-cleanup.c,v 1.2 2009/07/20 21:41:08 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <assert.h>
#include <unistd.h>


/* libdkim includes */
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
	assert(unlink(KEYFILE) == 0);

	return 0;
}
