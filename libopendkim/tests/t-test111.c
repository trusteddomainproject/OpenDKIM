/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "../dkim-internal.h"
#include "../util.h"

#define	MAXHEADER	4096

#define	QP_IN		"root=40example=2E=\r\ncom\n"
#define	QP_OUT		"root@example.com\n"

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
	int olen;
	char buf[BUFRSZ + 1];

	printf("*** quoted-printable decode\n");

	olen = dkim_qp_decode(QP_IN, buf, sizeof buf);
	assert(olen == strlen(QP_OUT));
	buf[olen] = '\0';
	assert(strcmp(QP_OUT, buf) == 0);

	return 0;
}
