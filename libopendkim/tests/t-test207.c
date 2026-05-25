/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, 2026, The Trusted Domain Project.
**    All rights reserved.
*/

/*
**  t-test207 -- regression: body without trailing CRLF and no l= tag still
**               raises DKIM_STAT_SYNTAX (issue #45)
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

#define MAXHEADER 4096

/* body content that does not end in CRLF */
#define TBODY_NOCRLF		"Body without CRLF"
#define TBODY_NOCRLF_LEN	17

static DKIM_STAT
key_lookup(DKIM *dkim, DKIM_SIGINFO *sig, unsigned char *buf, size_t buflen)
{
	assert(buf != NULL);
	memset(buf, '\0', buflen);
	strncpy((char *) buf, PUBLICKEY, buflen - 1);
	return DKIM_STAT_OK;
}

int
main(int argc, char **argv)
{
#ifdef TEST_KEEP_FILES
	u_int flags;
#endif /* TEST_KEEP_FILES */
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char sig_hdr[MAXHEADER + 1];
	unsigned char hdr[MAXHEADER + 1];

	printf("*** no l=: body without CRLF still raises syntax error\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

#ifdef TEST_KEEP_FILES
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	/* sign without body length limit (no l= in signature) */
	key = KEY;
	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	assert(dkim != NULL);

	status = dkim_header(dkim, HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);
	status = dkim_header(dkim, HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);
	status = dkim_header(dkim, HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);
	status = dkim_header(dkim, HEADER08, strlen(HEADER08));
	assert(status == DKIM_STAT_OK);
	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	/* sign with a proper CRLF-terminated body to get a valid signature */
	status = dkim_body(dkim, BODY00, strlen(BODY00));
	assert(status == DKIM_STAT_OK);
	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	memset(sig_hdr, '\0', sizeof sig_hdr);
	status = dkim_getsighdr(dkim, sig_hdr, sizeof sig_hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	/*
	**  Verify: feed a body without trailing CRLF.  Since the signature has
	**  no l= tag (canon_remain == -1), this must still raise DKIM_STAT_SYNTAX
	**  and not silently accept the malformed input.
	*/
	status = dkim_set_key_lookup(lib, key_lookup);
	assert(status == DKIM_STAT_OK);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	snprintf((char *) hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, sig_hdr);
	status = dkim_header(dkim, hdr, strlen((char *) hdr));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);
	status = dkim_header(dkim, HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);
	status = dkim_header(dkim, HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);
	status = dkim_header(dkim, HEADER08, strlen(HEADER08));
	assert(status == DKIM_STAT_OK);
	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	/* feed body WITHOUT trailing CRLF */
	status = dkim_body(dkim, (u_char *) TBODY_NOCRLF, TBODY_NOCRLF_LEN);
	assert(status == DKIM_STAT_OK);

	/* without l=, missing CRLF must still be a syntax error */
	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_SYNTAX);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
