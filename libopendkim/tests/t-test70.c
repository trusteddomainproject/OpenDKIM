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

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096
#define	MAXHDRCNT	64

#define SIG2 "v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID; z=Rec\r\n\teived:=20received=20data=201|Received:=20received=20data=202|Receiv\r\n\ted:=20received=20data=203=20part=201=0D=0A=09=20data=203=20part=202\r\n\t|From:=20Murray=20S.=20Kucherawy=20<msk@sendmail.com>|To:=20Sendmai\r\n\tl=20Test=20Address=20<sa-test@sendmail.net>|Date:=20Thu,=2005=20May\r\n\t=202005=2011:59:09=20-0700|Subject:=20DKIM=20test=20message|Message\r\n\t-ID:=20<439094BF.5010709@sendmail.com>; b=UfBRGUZXr6mCdxVNeavejTTWd\r\n\tWwZWarsUi90kj6K7AJWy4IWhYDpLPCt5tEYIQa4A6B/SkXHremA1QORVn8SW+7Z9xP4\r\n\tLNReV78biYbUnlncfHrEL3K7G3rR5bpa3bfNhdtGSVItLAg/f2XjHqiOQztjz1i4C/p\r\n\tD/pBm8XSWzlA="

#define	ALTHEADER02	"Received: received data 1 fghij"
#define	ALTHEADER03	"Received: received data 2 klmno"
#define	ALTHEADER04	"Received: received data 3 part 1\r\n\t data 3 part 2 pqrst"
#define ALTHEADER05	"From: Murray S Kucherawy <msk@sendmail.com>"

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
	int nhdrs;
	int nsigs;
	int ndiffs = 0;
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO **sigs;
	struct dkim_hdrdiff *diffs = NULL;
	dkim_canon_t hc;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char hdr[MAXHEADER + 1];
	unsigned char *ohdrs[MAXHDRCNT];

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	if (!dkim_libfeature(lib, DKIM_FEATURE_DIFFHEADERS) ||
	    !dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		printf("*** relaxed/simple rsa-sha256 verifying with header diffing SKIPPED\n");
		dkim_close(lib);
		return 0;
	}

	printf("*** relaxed/simple rsa-sha256 verifying with header diffing\n");

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

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, ALTHEADER02, strlen(ALTHEADER02));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, ALTHEADER03, strlen(ALTHEADER03));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, ALTHEADER04, strlen(ALTHEADER04));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, ALTHEADER05, strlen(ALTHEADER05));
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
	assert(status == DKIM_STAT_BADSIG);

	status = dkim_getsiglist(dkim, &sigs, &nsigs);
	assert(status == DKIM_STAT_OK);
	assert(sigs != NULL);
	assert(sigs[0] != NULL);
	assert(nsigs == 1);

	nhdrs = MAXHDRCNT;

	status = dkim_sig_getcanons(sigs[0], &hc, NULL);
	assert(status == DKIM_STAT_OK);
	assert(hc == DKIM_CANON_RELAXED);

	status = dkim_ohdrs(dkim, sigs[0], ohdrs, &nhdrs);
	assert(status == DKIM_STAT_OK);
	assert(nhdrs == 8);
	assert(strcmp(ohdrs[0], HEADER02) == 0);
	assert(strcmp(ohdrs[1], HEADER03) == 0);
	assert(strcmp(ohdrs[2], HEADER04) == 0);
	assert(strcmp(ohdrs[3], HEADER05) == 0);
	assert(strcmp(ohdrs[4], HEADER06) == 0);
	assert(strcmp(ohdrs[5], HEADER07) == 0);
	assert(strcmp(ohdrs[6], HEADER08) == 0);
	assert(strcmp(ohdrs[7], HEADER09) == 0);

	assert(dkim_sig_getcanons(sigs[0], &hc, NULL) == DKIM_STAT_OK);
	status = dkim_diffheaders(dkim, hc, 5, (char **) ohdrs, nhdrs,
	                          &diffs, &ndiffs);
	assert(status == DKIM_STAT_OK);
	assert(ndiffs == 1);
	assert(strcmp(diffs[0].hd_old, ohdrs[3]) == 0);
	assert(strcmp(diffs[0].hd_new, ALTHEADER05) == 0);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
