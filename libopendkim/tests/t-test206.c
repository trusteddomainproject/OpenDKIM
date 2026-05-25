/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, 2026, The Trusted Domain Project.
**    All rights reserved.
*/

/*
**  t-test206 -- sign+verify with l= where body does not end in CRLF should
**               succeed; verifies fix for issue #45 ("CRLF at end of body
**               missing" false positive when l= truncation is in use)
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

	printf("*** l= truncation: body without CRLF does not trigger syntax error\n");

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

	/*
	**  Sign with an explicit body length (produces l= in the signature).
	**  The body fed here does not end in CRLF, which is the scenario that
	**  previously triggered "CRLF at end of body missing" during sign too.
	*/
	key = KEY;
	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_RSASHA256,
	                 (ssize_t) TBODY_NOCRLF_LEN, &status);
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

	status = dkim_body(dkim, (u_char *) TBODY_NOCRLF, TBODY_NOCRLF_LEN);
	assert(status == DKIM_STAT_OK);

	/* sign eom must not fail with DKIM_STAT_SYNTAX */
	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	memset(sig_hdr, '\0', sizeof sig_hdr);
	status = dkim_getsighdr(dkim, sig_hdr, sizeof sig_hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	/*
	**  Verify: feed the same truncated body without CRLF.
	**  The verifier sees l= in the signature (canon_remain != -1) and must
	**  canonicalize the truncated body by appending CRLF rather than
	**  returning DKIM_STAT_SYNTAX.
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

	status = dkim_body(dkim, (u_char *) TBODY_NOCRLF, TBODY_NOCRLF_LEN);
	assert(status == DKIM_STAT_OK);

	/* verify eom must not fail with DKIM_STAT_SYNTAX */
	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
