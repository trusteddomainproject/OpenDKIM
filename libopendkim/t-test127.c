/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_test127_c_id[] = "@(#)$Id: t-test127.c,v 1.3 2009/10/22 19:51:15 cm-msk Exp $";
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
#include "dkim-canon.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define	TEST_KEEP_FILES	1

#define SIG2 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=NYK+FZAKLNXv1Oj/E6kV0EOStBU=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID;\r\n\tb=G9BZ+aZqLU7j3DnHe1s/qgrJagml7UDFUxOEQ/uCwWGvOgrDn3PBE/Nb1OwpGzuFJ\r\n\t AOCTpNGrK2sw4pfEAk+/uOBGjZsMTBe9uqIA7w3tQFkF3yIRv6zqa/rccbWa5d0wYn\r\n\t S534UHVEyPXjXQ5x/yspDXF+v3geyISQ+oHf9hro="

#define	CRLFBODY00	"test\r\n"

#define	BOUNDARY	9

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
	time_t fixed_time;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	struct dkim_dstring *buf;
	unsigned char hdr[MAXHEADER + 1];

	printf("*** relaxed/simple rsa-sha1 signing with split CRLFs and blank counting\n");

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

#ifdef TEST_KEEP_FILES
	/* set flags */
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA1, -1L, &status);
	assert(dkim != NULL);

	buf = (struct dkim_dstring *) dkim_dstring_new(dkim, 1024, 0);
	assert(buf != NULL);

	/* fix signing time */
	fixed_time = 1172620939;
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
	                    &fixed_time, sizeof fixed_time);

	status = dkim_header(dkim, HEADER02, strlen(HEADER02));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER03, strlen(HEADER03));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER04, strlen(HEADER04));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER08, strlen(HEADER08));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER09, strlen(HEADER09));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_dstring_cat(buf, CRLFBODY00);

	while (dkim_dstring_len(buf) < BOUNDARY)
		dkim_dstring_cat(buf, CRLF);

	dkim_dstring_cat(buf, CRLFBODY00);

	assert(dkim_dstring_len(buf) > BOUNDARY);

	status = dkim_body(dkim, (char *) dkim_dstring_get(buf), BOUNDARY);
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, (char *) (dkim_dstring_get(buf) + BOUNDARY),
	                   dkim_dstring_len(buf) - BOUNDARY);
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	assert(status == DKIM_STAT_OK);
	assert(strcmp(SIG2, hdr) == 0);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
