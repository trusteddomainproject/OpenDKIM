/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, 2026, The Trusted Domain Project.
**    All rights reserved.
*/

/*
**  t-test209 -- verify that dkim_header() accepts UTF-8 bytes in header
**               field bodies (RFC 8616 / EAI support).  Prior to the fix,
**               any byte > 0x7E in a field body returned DKIM_STAT_SYNTAX.
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
**  "Subject: Héllo wörld" encoded as UTF-8:
**    é = U+00E9 = 0xC3 0xA9
**    ö = U+00F6 = 0xC3 0xB6
*/
#define UTF8_SUBJECT	"Subject: H\xc3\xa9llo w\xc3\xb6rld"

int
main(int argc, char **argv)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;

	printf("*** UTF-8 header field body: accepted by dkim_header()\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	/*
	**  Feed a message with a UTF-8 Subject header and no DKIM-Signature.
	**  dkim_header() must return DKIM_STAT_OK for the UTF-8 header;
	**  dkim_eoh() must return DKIM_STAT_NOSIG (no signature present).
	*/

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	status = dkim_header(dkim,
	                     (u_char *) UTF8_SUBJECT,
	                     strlen(UTF8_SUBJECT));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_NOSIG);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
