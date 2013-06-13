/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG1 "v=1; a=rsa-sha1; c=relaxed/relaxed; d=example.com; s=test; t=1172620939; bh=WAB3bZtTHYLitirqQFGpaOBbkVY=; h=Content-class:Subject:Thread-Index:Date:X-MS-Has-Attach:From:To:Reply-To; b=gPbK/km0cEiwJBTjSUQ0oioRQNBMCJ6y6mSvg6S2z8xM57/BZx7I7c+eZ6IwtmCAXRMXJqiRixr9bxpcRU6KVkje3ofytiQ35bY7+h6RpV61lBFDxbMzdZfRmseGGeZGcGmmp6ICfi18f3KCiTOUrDptZ3+MVxSVeIdnVM6cLQ8="

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
	uint64_t fixed_time;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];
	unsigned char inhdr[MAXHEADER + 1];

	printf("*** zero margin testing\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

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

	dkim = dkim_sign(lib, JOBID "s1", NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_RSASHA1, -1L, &status);
	assert(dkim != NULL);

	status = dkim_set_margin(dkim, 0);
	assert(status == DKIM_STAT_OK);

	/* fix signing time */
	fixed_time = 1172620939;
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
	                    &fixed_time, sizeof fixed_time);

#define	HEADER0		"Content-class: urn:content-classes:message"
#define HEADER1		"Subject: This is a sample message from a DKIM tester"
#define	HEADER2		"Thread-Index: 1234567tgjdoigj"
#define	HEADER3		"Date: Wed, 18 Jul 2007 10:48:38 -0700"
#define	HEADER4		"X-MS-Has-Attach:"
#define HEADER5		"From: \"DKIM tester\" <tester@yahoo.com>"
#define	HEADER6		"To: \"DKIM tester\" <tester@yahoo.com>"
#define HEADER7		"Reply-To: \"DKIM tester\" <tester@yahoo.com>"
#define	BODY		"Test\r\n"

	status = dkim_header(dkim, HEADER0, strlen(HEADER0));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER1, strlen(HEADER1));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER2, strlen(HEADER2));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER3, strlen(HEADER3));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER4, strlen(HEADER4));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER5, strlen(HEADER5));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER6, strlen(HEADER6));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER7, strlen(HEADER7));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY, strlen(BODY));
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(dkim, hdr, sizeof hdr, 0);
	assert(status == DKIM_STAT_OK);
	assert(strcmp(SIG1, hdr) == 0);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));

	dkim = dkim_verify(lib, JOBID "v1", NULL, &status);
	assert(dkim != NULL);

	status = dkim_set_margin(dkim, 0);
	assert(status == DKIM_STAT_INVALID);

	snprintf(inhdr, sizeof inhdr, "%s: %s", DKIM_SIGNHEADER, hdr);
	status = dkim_header(dkim, inhdr, strlen(inhdr));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER0, strlen(HEADER0));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER1, strlen(HEADER1));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER2, strlen(HEADER2));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER3, strlen(HEADER3));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER4, strlen(HEADER4));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER5, strlen(HEADER5));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER6, strlen(HEADER6));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER7, strlen(HEADER7));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY, strlen(BODY));
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	status = dkim_set_margin(dkim, DKIM_HDRMARGIN);
	assert(status == DKIM_STAT_INVALID);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
