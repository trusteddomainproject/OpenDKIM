/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, 2026, The Trusted Domain Project.
**    All rights reserved.
*/

/*
**  t-test208 -- verify that a malformed DKIM-Signature header produces
**               DKIM_STAT_SYNTAX from dkim_header() and DKIM_STAT_NOSIG
**               from dkim_eoh(), confirming the library behaviour that
**               the mlfi_eoh() fix for issue #194 relies on.
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

int
main(int argc, char **argv)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;

	printf("*** malformed DKIM-Signature: SYNTAX from dkim_header, NOSIG from dkim_eoh\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	/*
	**  Feed a message whose only DKIM-Signature has no valid tag-value
	**  pairs.  dkim_header() must return DKIM_STAT_SYNTAX; the handle
	**  must remain usable; dkim_eoh() must return DKIM_STAT_NOSIG
	**  (the bad sig is skipped, leaving no valid signatures).
	*/

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	status = dkim_header(dkim,
	                     (u_char *) "DKIM-Signature: eeee",
	                     strlen("DKIM-Signature: eeee"));
	assert(status == DKIM_STAT_SYNTAX);

	status = dkim_header(dkim, (u_char *) HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, (u_char *) HEADER08, strlen(HEADER08));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_NOSIG);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
