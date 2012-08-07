/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

/* template */
#define SIG "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="

#define SIG1 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG2 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; l=-1; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG3 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; l=all; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG4 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; q=foo; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG5 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; q=dns/foo; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG6 "v=1; a=rsa-sha1; c=relaxed/simple; s=test;\r\n\tt=1172620939; q=dns/foo; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG7 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; \r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG8 "v=1; a=rsa-sha1; c=relaxed/simple; d=; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG9 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG10 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG11 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG12 "v=1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG13 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID"
#define SIG14 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b="
#define SIG15 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8f="
#define SIG16 "v=1; a=rsa-sha0; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG17 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU=; x"
#define SIG18 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=%ld; x=%ld; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG19 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; x=never; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG20 "v=1; =rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG21 "v=1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG22 "v=1; a=rsa-sha1; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="
#define SIG23 "a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="

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
	int nsigs;
	int len;
	DKIM_STAT status;
	dkim_canon_t bcanon;
	dkim_canon_t hcanon;
	time_t now;
	DKIM *dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO **sigs;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char hdr[MAXHEADER + 1];

	printf("*** detection of various signature abnormalities\n");

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

	/* missing h= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG1);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* negative l= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* bogus l= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG3);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* bogus q= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG4);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* bogus q= option */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG5);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* missing d= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG6);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* missing s= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG7);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* empty d= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG8);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* empty s= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG9);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* missing bh= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG10);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* empty bh= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG11);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* missing a= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG12);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* missing b= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG13);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* empty b= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG14);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* corrupt b= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG15);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* invalid a= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG16);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* trailing tag with no value */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG17);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* x= < t= */
        (void) time(&now);
        len = snprintf(hdr, sizeof hdr, "%s: ", DKIM_SIGNHEADER);
        snprintf(hdr + len, sizeof hdr - len, SIG18, (long) (now + 25),
	         (long) (now + 10));
        status = dkim_header(dkim, hdr, strlen(hdr));
        assert(status == DKIM_STAT_OK);

	/* bogus x= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG19);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* control characters */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG20);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* missing a= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG21);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	/* missing c= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG22);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	/* missing v= */
	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG23);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_SYNTAX);

	status = dkim_header(dkim, HEADER01, strlen(HEADER01));
	assert(status == DKIM_STAT_OK);

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

	status = dkim_getsiglist(dkim, &sigs, &nsigs);
	assert(status == DKIM_STAT_OK);
	assert(nsigs == 13);

	assert(dkim_sig_geterror(sigs[0]) == DKIM_SIGERROR_INVALID_L);
	assert(dkim_sig_geterror(sigs[1]) == DKIM_SIGERROR_INVALID_L);
	assert(dkim_sig_geterror(sigs[2]) == DKIM_SIGERROR_INVALID_Q);
	assert(dkim_sig_geterror(sigs[3]) == DKIM_SIGERROR_INVALID_QO);
	assert(dkim_sig_geterror(sigs[4]) == DKIM_SIGERROR_EMPTY_D);
	assert(dkim_sig_geterror(sigs[5]) == DKIM_SIGERROR_EMPTY_S);
	assert(dkim_sig_geterror(sigs[6]) == DKIM_SIGERROR_MISSING_BH);
	assert(dkim_sig_geterror(sigs[7]) == DKIM_SIGERROR_EMPTY_BH);
	assert(dkim_sig_geterror(sigs[8]) == DKIM_SIGERROR_EMPTY_B);
	assert(dkim_sig_geterror(sigs[9]) == DKIM_SIGERROR_CORRUPT_B);
	assert(dkim_sig_geterror(sigs[10]) == DKIM_SIGERROR_INVALID_A);
	assert(dkim_sig_geterror(sigs[11]) == DKIM_SIGERROR_TIMESTAMPS);

	assert(dkim_sig_geterror(sigs[12]) == DKIM_SIGERROR_BADSIG);
	status = dkim_sig_getcanons(sigs[12], &hcanon, &bcanon);
	assert(status == DKIM_STAT_OK);
	assert(hcanon == DKIM_CANON_SIMPLE);
	assert(bcanon == DKIM_CANON_SIMPLE);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
