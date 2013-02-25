/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, The Trusted Domain Project.
**    All rights reserved.
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
#include "t-testdata.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

#define	MAXHEADER	4096

#define	MAXMSGSIZE	16384

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
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char hdr[MAXHEADER + 1];
	unsigned char buf[MAXMSGSIZE];

	printf("*** relaxed/simple rsa-sha1 verifying using chunking API (single chunk)\n");

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

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	memset(buf, '\0', sizeof buf);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	strlcpy(buf, hdr, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER01, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER02, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER03, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER04, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER05, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER06, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER07, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER08, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, HEADER09, MAXMSGSIZE);
	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, CRLF, MAXMSGSIZE);

	strlcat(buf, BODY00, MAXMSGSIZE);
	strlcat(buf, BODY01, MAXMSGSIZE);
	strlcat(buf, BODY01A, MAXMSGSIZE);
	strlcat(buf, BODY01B, MAXMSGSIZE);
	strlcat(buf, BODY01C, MAXMSGSIZE);
	strlcat(buf, BODY01D, MAXMSGSIZE);
	strlcat(buf, BODY01E, MAXMSGSIZE);
	strlcat(buf, BODY02, MAXMSGSIZE);
	strlcat(buf, BODY03, MAXMSGSIZE);
	strlcat(buf, BODY04, MAXMSGSIZE);
	strlcat(buf, BODY03, MAXMSGSIZE);
	strlcat(buf, BODY03, MAXMSGSIZE);
	strlcat(buf, BODY05, MAXMSGSIZE);
	strlcat(buf, BODY03, MAXMSGSIZE);
	strlcat(buf, BODY03, MAXMSGSIZE);

	status = dkim_chunk(dkim, buf, strlen(buf));
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
