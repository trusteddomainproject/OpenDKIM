/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_test88_c_id[] = "@(#)$Id: t-test88.c,v 1.4 2009/10/22 19:51:15 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>


/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-types.h"
#include "dkim-util.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG2 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="

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
#ifdef TEST_KEEP_FILES
	u_int flags;
#endif /* TEST_KEEP_FILES */
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	struct dkim_dstring *buf;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char hdr[MAXHEADER + 1];

	printf("*** relaxed/simple rsa-sha1 verifying using chunking API (single chunk)\n");

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

#ifdef TEST_KEEP_FILES
	/* set flags */
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	buf = (struct dkim_dstring *) dkim_dstring_new(dkim, 1024, 0);
	assert(buf != NULL);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	dkim_dstring_cat(buf, hdr);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER01);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER02);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER03);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER04);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER05);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER06);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER07);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER08);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, HEADER09);
	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, BODY00);
	dkim_dstring_cat(buf, BODY01);
	dkim_dstring_cat(buf, BODY01A);
	dkim_dstring_cat(buf, BODY01B);
	dkim_dstring_cat(buf, BODY01C);
	dkim_dstring_cat(buf, BODY01D);
	dkim_dstring_cat(buf, BODY01E);
	dkim_dstring_cat(buf, BODY02);
	dkim_dstring_cat(buf, BODY03);
	dkim_dstring_cat(buf, BODY04);
	dkim_dstring_cat(buf, BODY03);
	dkim_dstring_cat(buf, BODY03);
	dkim_dstring_cat(buf, BODY05);
	dkim_dstring_cat(buf, BODY03);
	dkim_dstring_cat(buf, BODY03);

	status = dkim_chunk(dkim, (char *) dkim_dstring_get(buf),
	                    dkim_dstring_len(buf));
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_INVALID);

	status = dkim_chunk(dkim, NULL, 0);
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
