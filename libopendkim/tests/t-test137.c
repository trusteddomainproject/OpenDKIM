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
#include <arpa/nameser.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG1 "v=1; a=rsa-sha1; c=simple/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=V+wiYd1cE70A40eDNUtYwU\r\n\tvqi727NN/vVo/OdC7jG4zvztIXCRjPKDXEfiZdW+6PZ08M4zA3GmLZI2p+IJTza+VDQ\r\n\tbohnvIUSRR6q9+Nddqz1qTCL0gNM5d64xKwrLUesk/3wb/Cvua6Atr+VBMFVCwQmSDf\r\n\trs4brLkqMyFOkCE="
#define SIG2 "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID; b=12345678Y3y\r\n\tVeA3WZdCZl1sGuOZNC3BBRhtGCOExkZdw5xQoGPvSX/q6AC1SAJvOUWOri95AZAUGs0\r\n\t/bIDzzt23ei9jc+rptlavrl/5ijMrl6ShmvkACk6It62KPkJcDpoGfi5AZkrfX1Ou/z\r\n\tqGg5xJX86Kqd7FgNolMg7PbfyWliK2Yb84="
#define SIG3 "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID; b=12345678Y4y\r\n\tVeA3WZdCZl1sGuOZNC3BBRhtGCOExkZdw5xQoGPvSX/q6AC1SAJvOUWOri95AZAUGs0\r\n\t/bIDzzt23ei9jc+rptlavrl/5ijMrl6ShmvkACk6It62KPkJcDpoGfi5AZkrfX1Ou/z\r\n\tqGg5xJX86Kqd7FgNolMg7PbfyWliK2Yb84="

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
	size_t hdrlen;
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_SIGINFO **sigs;
	DKIM_LIB *lib;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char hdr[MAXHEADER + 1];

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	if (!dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		printf("*** simple/simple rsa-sha256 signature substrings SKIPPED\n");
		dkim_close(lib);
		return 0;
	}

	printf("*** simple/simple rsa-sha256 verifying signature substrings\n");

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

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG1);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

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
	assert(nsigs == 2);

	memset(hdr, '\0', sizeof hdr);
	hdrlen = sizeof hdr - 1;
	status = dkim_get_sigsubstring(dkim, sigs[0], hdr, &hdrlen);
	assert(status == DKIM_STAT_OK);
	assert(hdrlen == 8);
	assert(strcmp(hdr, "V+wiYd1c") == 0);
	status = dkim_get_sigsubstring(dkim, sigs[1], hdr, &hdrlen);
	assert(status == DKIM_STAT_OK);
	assert(hdrlen == 8);
	assert(strcmp(hdr, "12345678") == 0);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG1);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG3);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

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
	assert(nsigs == 3);

	memset(hdr, '\0', sizeof hdr);
	hdrlen = sizeof hdr - 1;
	status = dkim_get_sigsubstring(dkim, sigs[0], hdr, &hdrlen);
	assert(status == DKIM_STAT_OK);
	assert(hdrlen == 10);
	assert(strcmp(hdr, "V+wiYd1cE7") == 0);
	status = dkim_get_sigsubstring(dkim, sigs[1], hdr, &hdrlen);
	assert(status == DKIM_STAT_OK);
	assert(hdrlen == 10);
	assert(strcmp(hdr, "12345678Y3") == 0);
	status = dkim_get_sigsubstring(dkim, sigs[2], hdr, &hdrlen);
	assert(status == DKIM_STAT_OK);
	assert(hdrlen == 10);
	assert(strcmp(hdr, "12345678Y4") == 0);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
