/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_test42_c_id[] = "@(#)$Id: t-test42.c,v 1.2 2009/07/20 21:41:08 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <arpa/nameser.h>



/* libdkim includes */
#include "dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG2 "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID; b=Y3y\r\n\tVeA3WZdCZl1sGuOZNC3BBRhtGCOExkZdw5xQoGPvSX/q6AC1SAJvOUWOri95AZAUGs0\r\n\t/bIDzzt23ei9jc+rptlavrl/5ijMrl6ShmvkACk6It62KPkJcDpoGfi5AZkrfX1Ou/z\r\n\tqGg5xJX86Kqd7FgNolMg7PbfyWliK2Yb84="

int pl;
int kl;

/*
**  POLICY_LOOKUP -- policy lookup
**
**  Parameters:
**  	dkim -- DKIM handle
**  	query -- string to query
**  	excheck -- existence check?
**  	buf -- where to write the result
**  	buflen -- how much space is available at "buf"
**  	qstatus -- query status (returned)
**
**  Return value:
**  	0 -- operation completed
**  	-1 -- error
*/

int
policy_lookup(DKIM *dkim, unsigned char *query, bool excheck,
              unsigned char *buf, size_t buflen, int *qstatus)
{
	assert(dkim != NULL);
	assert(query != NULL);
	assert(buf != NULL);
	assert(qstatus != NULL);

	pl = 1;

	strlcpy(buf, DKIM_POLICY_DEFAULTTXT, buflen);
	*qstatus = NOERROR;

	return 0;
}

/*
**  KEY_LOOKUP -- key lookup
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	buf -- where to write the result
**  	buflen -- how much space is available at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
key_lookup(DKIM *dkim, DKIM_SIGINFO *sig, unsigned char *buf, size_t buflen)
{
	const char *selector;
	const char *domain;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(buf != NULL);

	selector = dkim_sig_getselector(sig);
	assert(selector != NULL);
	assert(strcmp(selector, SELECTOR) == 0);

	domain = dkim_sig_getdomain(sig);
	assert(domain != NULL);
	assert(strcmp(domain, DOMAIN) == 0);

	memset(buf, '\0', buflen);
	strncpy(buf, PUBLICKEY, buflen);

	kl = 1;

	return DKIM_STAT_OK;
}

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
#ifndef DKIM_SIGN_RSASHA256
	printf("*** simple/simple rsa-sha256 verifying with key/policy callbacks SKIPPED\n");

#else /* ! DKIM_SIGN_RSASHA256 */

# ifdef TEST_KEEP_FILES
	u_int flags;
# endif /* TEST_KEEP_FILES */
	int testpolicy;
	int suspicious;
	DKIM_STAT status;
	dkim_policy_t pcode;
	DKIM *dkim;
	DKIM_LIB *lib;
	unsigned char hdr[MAXHEADER + 1];

	pl = 0;
	kl = 0;

	printf("*** simple/simple rsa-sha256 verifying with key/policy callbacks\n");

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

# ifdef TEST_KEEP_FILES
	/* set flags */
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
# endif /* TEST_KEEP_FILES */

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	(void) dkim_set_key_lookup(lib, key_lookup);
	(void) dkim_set_policy_lookup(lib, policy_lookup);

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

	status = dkim_body(dkim, BODY00, strlen(BODY00));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY01, strlen(BODY01));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY01A, strlen(BODY01A));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01B, strlen(BODY01B));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01C, strlen(BODY01C));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01D, strlen(BODY01D));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01E, strlen(BODY01E));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY02, strlen(BODY02));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY04, strlen(BODY04));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY05, strlen(BODY05));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	testpolicy = 0;
	suspicious = 0;
	status = dkim_policy(dkim, &pcode, NULL);
	assert(status == DKIM_STAT_OK);
	assert(pcode == DKIM_POLICY_UNKNOWN);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	assert(pl == 1);
	assert(kl == 1);

	dkim_close(lib);
#endif /* ! DKIM_SIGN_RSASHA256 */

	return 0;
}
