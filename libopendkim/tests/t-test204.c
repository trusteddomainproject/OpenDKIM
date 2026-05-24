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

#define MAXHEADER 4096

/*
**  key_lookup -- return public key for a given selector/domain pair
**
**  SELECTOR ("test") + DOMAIN -> RSA public key
**  SELECTOR2 ("brisbane") + DOMAIN -> Ed25519 public key
*/

static DKIM_STAT
key_lookup(DKIM *dkim, DKIM_SIGINFO *sig, unsigned char *buf, size_t buflen)
{
	const char *selector;
	const char *domain;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(buf != NULL);

	selector = dkim_sig_getselector(sig);
	domain = dkim_sig_getdomain(sig);

	assert(selector != NULL);
	assert(domain != NULL);
	assert(strcmp(domain, DOMAIN) == 0);

	memset(buf, '\0', buflen);

	if (strcmp(selector, SELECTOR) == 0)
		strncpy((char *) buf, PUBLICKEY, buflen - 1);
	else if (strcmp(selector, SELECTOR2) == 0)
		strncpy((char *) buf, RFC8463_ED25519PUBLICKEY, buflen - 1);
	else
		assert(0); /* unexpected selector */

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
#ifdef TEST_KEEP_FILES
	u_int flags;
#endif /* TEST_KEEP_FILES */
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO **sigs;
	int nsigs;
	dkim_sigkey_t key;
	unsigned char rsa_sig[MAXHEADER + 1];
	unsigned char ed25519_sig[MAXHEADER + 1];
	unsigned char hdr[MAXHEADER + 1];

	printf("*** relaxed/relaxed multi-signing (RSA-SHA256 + Ed25519), both verify\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	if (!dkim_libfeature(lib, DKIM_FEATURE_ED25519) ||
	    !dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		printf("*** relaxed/relaxed multi-signing (RSA-SHA256 + Ed25519), both verify SKIPPED\n");
		dkim_close(lib);
		return 0;
	}

#ifdef TEST_KEEP_FILES
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	/* sign with RSA-SHA256 */
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
	status = dkim_header(dkim, HEADER09, strlen(HEADER09));
	assert(status == DKIM_STAT_OK);
	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY00, strlen(BODY00));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01, strlen(BODY01));
	assert(status == DKIM_STAT_OK);
	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	memset(rsa_sig, '\0', sizeof rsa_sig);
	status = dkim_getsighdr(dkim, rsa_sig, sizeof rsa_sig,
	                        strlen(DKIM_SIGNHEADER) + 2);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	/* sign with Ed25519-SHA256 */
	key = RFC8463_ED25519KEY;
	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR2, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_ED25519SHA256, -1L, &status);
	assert(dkim != NULL);

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
	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	memset(ed25519_sig, '\0', sizeof ed25519_sig);
	status = dkim_getsighdr(dkim, ed25519_sig, sizeof ed25519_sig,
	                        strlen(DKIM_SIGNHEADER) + 2);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	/* verify both signatures */
	status = dkim_set_key_lookup(lib, key_lookup);
	assert(status == DKIM_STAT_OK);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	snprintf((char *) hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, rsa_sig);
	status = dkim_header(dkim, hdr, strlen((char *) hdr));
	assert(status == DKIM_STAT_OK);

	snprintf((char *) hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, ed25519_sig);
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
	status = dkim_header(dkim, HEADER09, strlen(HEADER09));
	assert(status == DKIM_STAT_OK);
	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY00, strlen(BODY00));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01, strlen(BODY01));
	assert(status == DKIM_STAT_OK);
	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	nsigs = 0;
	assert(dkim_getsiglist(dkim, &sigs, &nsigs) == DKIM_STAT_OK);
	assert(nsigs == 2);

	assert(dkim_sig_geterror(sigs[0]) == DKIM_SIGERROR_OK);
	assert(dkim_sig_geterror(sigs[1]) == DKIM_SIGERROR_OK);
	assert(DKIM_SIG_CHECK(sigs[0]));
	assert(DKIM_SIG_CHECK(sigs[1]));

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
