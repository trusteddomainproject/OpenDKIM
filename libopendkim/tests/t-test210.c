/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, 2026, The Trusted Domain Project.
**    All rights reserved.
*/

/*
**  t-test210 -- verify that a DKIM-Signature with a UTF-8 local-part in the
**               i= tag is parsed without error (RFC 8616 section 4).  Prior
**               to the fix, dkim_process_set() rejected any non-ASCII byte
**               unconditionally, causing a valid EAI signature to be treated
**               as malformed.
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

/*
**  A syntactically valid DKIM-Signature whose i= local-part contains UTF-8:
**    ø = U+00F8 = 0xC3 0xB8  (so "søren" has a non-ASCII byte)
**  The b= and bh= values are well-formed base64 but not cryptographically
**  valid; we only exercise parsing here, not verification.
*/
#define UTF8_DKIM_SIG \
	"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;" \
	" d=" DOMAIN "; s=" SELECTOR \
	"; i=s\xc3\xb8ren@" DOMAIN \
	"; h=from:to:subject:date;" \
	" bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;" \
	" b=dGVzdA=="

int
main(int argc, char **argv)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;

	printf("*** UTF-8 i= local-part in DKIM-Signature: parsed without error\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	/*
	**  Feed a DKIM-Signature that is structurally valid and contains a
	**  UTF-8 local-part in i=.  dkim_header() must return DKIM_STAT_OK
	**  (not DKIM_STAT_SYNTAX).  dkim_eoh() must return DKIM_STAT_OK,
	**  confirming the signature was parsed and counted rather than
	**  discarded as malformed due to the UTF-8 bytes.
	*/

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	status = dkim_header(dkim,
	                     (u_char *) UTF8_DKIM_SIG,
	                     strlen(UTF8_DKIM_SIG));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER08, strlen(HEADER08));
	assert(status == DKIM_STAT_OK);

	/*
	**  dkim_eoh() returns DKIM_STAT_OK when at least one signature was
	**  parsed successfully.  A return of DKIM_STAT_NOSIG here would mean
	**  the signature was silently discarded due to the UTF-8 bytes.
	*/
	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
