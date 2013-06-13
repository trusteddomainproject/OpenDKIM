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

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG2 "v=1; a=rsa-sha1; c=simple/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID;\r\n\tb=RqQ3gVSDB3xUQQKQh1vCFBqu306DAVbz776m3ZK0Kgs6FJwgjb7z9McilKmYludRt\r\n\t GAt3WADSvGkSKUNShTh0/yyww5a7dLllFBKERievrA6WovExPrKXte1/4Z/6TiRWtD\r\n\t ak0ef7bir2japcq0hxet3BKHOZYm0MDDskkOFecg=;"

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
	_Bool testkey;
	u_int flags;
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char buf[10240];

	printf("*** simple/simple rsa-sha1 verifying with chunking, FIXCRLF, and \"b=...;\"\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	/* set flags */
	flags = DKIM_LIBFLAGS_FIXCRLF;
#ifdef TEST_KEEP_FILES
	flags |= (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
#endif /* TEST_KEEP_FILES */
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));

	dkim = dkim_verify(lib, "test153", NULL, &status);
	assert(dkim != NULL);

	memset(buf, '\0', sizeof buf);

	strlcat(buf, DKIM_SIGNHEADER ": ", sizeof buf);
	strlcat(buf, SIG2, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER02, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER03, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER04, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER05, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER06, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER07, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER08, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, HEADER09, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, CRLF, sizeof buf);
	strlcat(buf, BODY00, sizeof buf);
	strlcat(buf, BODY01, sizeof buf);
	strlcat(buf, BODY01A, sizeof buf);
	strlcat(buf, BODY01B, sizeof buf);
	strlcat(buf, BODY01C, sizeof buf);
	strlcat(buf, BODY01D, sizeof buf);
	strlcat(buf, BODY01E, sizeof buf);
	strlcat(buf, BODY02, sizeof buf);
	strlcat(buf, BODY03, sizeof buf);
	strlcat(buf, BODY04, sizeof buf);
	strlcat(buf, BODY03, sizeof buf);
	strlcat(buf, BODY03, sizeof buf);
	strlcat(buf, BODY05, sizeof buf);
	strlcat(buf, BODY03, sizeof buf);
	strlcat(buf, BODY03, sizeof buf);

	status = dkim_chunk(dkim, buf, strlen(buf));
	assert(status == DKIM_STAT_OK);

	status = dkim_chunk(dkim, NULL, 0);
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, &testkey);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
