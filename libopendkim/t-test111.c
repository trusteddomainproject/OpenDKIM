/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_test111_c_id[] = "@(#)$Id: t-test111.c,v 1.5 2009/11/11 19:39:59 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* libopendkim includes */
#include "dkim.h"
#include "dkim-internal.h"
#include "util.h"

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

	memset(buf, '\0', sizeof buf);

	olen = dkim_qp_decode(QP_IN, buf, sizeof buf);
	assert(olen == strlen(QP_OUT));
	assert(strcmp(QP_OUT, buf) == 0);

	return 0;
}
