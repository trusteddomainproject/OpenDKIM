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
#include <stdlib.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG1 "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi81=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID; b=Y3y\r\n\tVeA3WZdCZl1sGuOZNC3BBRhtGCOExkZdw5xQoGPvSX/q6AC1SAJvOUWOri95AZAUGs0\r\n\t/bIDzzt23ei9jc+rptlavrl/5ijMrl6ShmvkACk6It62KPkJcDpoGfi5AZkrfX1Ou/z\r\n\tqGg5xJX86Kqd7FgNolMg7PbfyWliK2Yb84="
#define SIG2 "v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID; b=hNR\r\n\tIcA7ZG6mZL9GPr5E9rJPQBy0DNnPSNAqYmtpbHJjhzWj3fsUKXDCEl8vJki6VuP0hDA\r\n\t4wRRJ6hkD0/u9iY2O+7xwAyuzkC3Z719CuGidnqlJt/1kJ4QW4KlcWJcj2v8SjD475G\r\n\tchVu0268Cz9PTJWSEqg/WZfWLQrji0gmy0="

struct local_sig
{
	const char *	ls_domain;
	const char *	ls_signalg;
	const char *	ls_timestamp;
	const char *	ls_canon;
	const char *	ls_version;
	const char *	ls_selector;
	const char *	ls_bodyhash;
	const char *	ls_hdrlist;
	const char *	ls_signature;
};

/*
**  ALLOC_HANDLE -- allocate a local signature handle
**
**  Parameters:
**  	ignored -- a (void *) which we don't need
**
**  Return value:
**  	Pointer to a local signature handle.
*/

void *
alloc_handle(void *ignored)
{
	void *new;

	new = (void *) malloc(sizeof(struct local_sig));
	assert(new != NULL);
	memset(new, '\0', sizeof(struct local_sig));
	return new;
}

/*
**  TAGVALUES -- process a tag/value pair given a DKIM_SIG handle
**
**  Parameters:
**  	user -- (void *) referring to a struct local_sig
**  	pcode -- parameter code being reported (DKIM_PARAM_*)
**  	param -- pointer to the text form of the tag
**  	value -- pointer to the text form of the value
**
**  Return value:
**  	None.
*/

void
tagvalues(void *user, dkim_param_t pcode,
          const u_char *param, const u_char *value)
{
	struct local_sig *ls = (struct local_sig *) user;

	switch (pcode)
	{
	  case DKIM_PARAM_DOMAIN:
		ls->ls_domain = value;
		break;

	  case DKIM_PARAM_SIGNATURE:
		ls->ls_signature = value;
		break;

	  case DKIM_PARAM_HDRLIST:
		ls->ls_hdrlist = value;
		break;

	  case DKIM_PARAM_BODYHASH:
		ls->ls_bodyhash = value;
		break;

	  case DKIM_PARAM_SELECTOR:
		ls->ls_selector = value;
		break;

	  case DKIM_PARAM_VERSION:
		ls->ls_version = value;
		break;

	  case DKIM_PARAM_CANONALG:
		ls->ls_canon = value;
		break;

	  case DKIM_PARAM_TIMESTAMP:
		ls->ls_timestamp = value;
		break;

	  case DKIM_PARAM_SIGNALG:
		ls->ls_signalg = value;
		break;

	  case DKIM_PARAM_UNKNOWN:
		assert(0);
	} 
}

/*
**  PRESCREEN -- verify the contents of a local_sig structure
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sigs -- array of DKIM_SIGINFO pointers
**  	nsigs -- how many sigs there were
**
**  Return value:
**  	DKIM_CBSTAT_CONTINUE (assuming no assertions fire).
*/

DKIM_CBSTAT
prescreen(DKIM *dkim, DKIM_SIGINFO **sigs, int nsigs)
{
	DKIM_SIGINFO *siginfo;

	assert(dkim != NULL);
	assert(sigs != NULL);
	assert(nsigs == 2);

	/*
	**  Arrange to swap order since we know for this test that the second
	**  one is good and the first one is bad.
	*/

	siginfo = sigs[1];
	sigs[1] = sigs[0];
	sigs[0] = siginfo;

	return DKIM_CBSTAT_CONTINUE;
}

/*
**  FREE_HANDLE -- deallocate a local signature handle
**
**  Parameters:
**  	ignored -- a (void *) which we don't need
**  	handle -- pointer to the struct local_sig to be deallocated
**
**  Return value:
**  	None.
*/

void
free_handle(void *ignored, void *handle)
{
	assert(handle != NULL);

	free(handle);
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
#ifdef TEST_KEEP_FILES
	u_int flags;
#endif /* TEST_KEEP_FILES */
	DKIM_STAT status;
	DKIM *dkim;
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
		printf("*** relaxed/simple rsa-sha256 signature reordering SKIPPED\n");
		dkim_close(lib);
		return 0;
	}

	printf("*** relaxed/simple rsa-sha256 signature reordering\n");

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

	(void) dkim_set_signature_handle(lib, alloc_handle);
	(void) dkim_set_signature_handle_free(lib, free_handle);
	(void) dkim_set_signature_tagvalues(lib, tagvalues);
	(void) dkim_set_prescreen(lib, prescreen);

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

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
