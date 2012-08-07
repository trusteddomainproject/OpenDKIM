/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <arpa/nameser.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"
#include "../dkim-strl.h"

#define	MAXHEADER	4096

#define	SIG1 "v=1; a=rsa-sha256; c=relaxed/simple; d=sendmail.com; s=test; t=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=; h=Received:Received:Received:From:To:Date:Subject:Message-ID; b=HLU6+LztURsYvmqEEHX74Vx9dR7tRtUDIlgRws7WCk5D8HqHx9Z2sSWkPqlkbh+meXydZWexg42oxOE94p6BLa5rDhJopSvlHBeZeCLp0U+JIkk7TlLWv82K+2Tbykx1b8bYuriFafkyPYhm+SFHs0zirGDJz71dYnTMc229znM="
#define SIG2 "v=1; a=rsa-sha256; c=relaxed/simple; d=sendmail.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID; b=HLU\r\n\t6+LztURsYvmqEEHX74Vx9dR7tRtUDIlgRws7WCk5D8HqHx9Z2sSWkPqlkbh+meXydZW\r\n\texg42oxOE94p6BLa5rDhJopSvlHBeZeCLp0U+JIkk7TlLWv82K+2Tbykx1b8bYuriFa\r\n\tfkyPYhm+SFHs0zirGDJz71dYnTMc229znM="

#define	DKIM_TEST_POLICY	"dkim=discardable"

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
policy_lookup(DKIM *dkim, unsigned char *query, _Bool excheck,
              unsigned char *buf, size_t buflen, int *qstatus)
{
	assert(dkim != NULL);
	assert(query != NULL);
	assert(buf != NULL);
	assert(qstatus != NULL);

#define	GOODQUERY	"_adsp._domainkey.sendmail.com"
	if (excheck)
		*qstatus = NOERROR;
	else if (strcmp(query, GOODQUERY) != 0)
		*qstatus = NXDOMAIN;
	else
		strlcpy(buf, DKIM_TEST_POLICY, buflen);

	return 0;
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
# ifdef TEST_KEEP_FILES
	u_int flags;
# endif /* TEST_KEEP_FILES */
	int presult;
	dkim_policy_t pcode;
	DKIM_STAT status;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	DKIM *dkim;
	DKIM_LIB *lib;
	unsigned char hdr[MAXHEADER + 1];

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	if (!dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		printf("*** relaxed/simple rsa-sha256 verifying subdomain with i=/d= mismatch and \"discardable\" policy SKIPPED\n");
		dkim_close(lib);
		return 0;
	}

	printf("*** relaxed/simple rsa-sha256 verifying subdomain with i=/d= mismatch and \"discardable\" policy\n");

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

#define	XHEADER05	"From: Murray S. Kucherawy <msk@eng.sendmail.com>"
	status = dkim_header(dkim, XHEADER05, strlen(XHEADER05));
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

	status = dkim_policy(dkim, &pcode, NULL, NULL);
	assert(status == DKIM_STAT_OK);

	presult = dkim_getpresult(dkim);
	assert(presult == DKIM_PRESULT_NONE);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
