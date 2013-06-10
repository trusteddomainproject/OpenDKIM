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
#include <stdlib.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

struct dkim_dstring;

/* libopendkim includes */
#include "../dkim-internal.h"
#include "../dkim-util.h"

#define	TESTBUFRSZ	4096
#define	TESTJOBID	"x"
#define	TESTSTRING	"Hello, world!\n"

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
	int c;
	DKIM_STAT status;
	DKIM_LIB *lib;
	DKIM *dkim;
	struct dkim_dstring *dstring;
	char *p;
	char testbuf[TESTBUFRSZ + 1];

	printf("*** exercise dstring functions\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);
	dkim = dkim_verify(lib, TESTJOBID, NULL, &status);
	assert(dkim != NULL);

	/* make a dstring */
	dstring = dkim_dstring_new(dkim, 0, 0);
	assert(dstring != NULL);

	/* confirm that it's empty */
	assert(dkim_dstring_len(dstring) == 0);
	p = dkim_dstring_get(dstring);
	assert(p != NULL);
	assert(p[0] == '\0');

	/* put something in it */
	for (c = 0; c < sizeof testbuf; c++)
		testbuf[c] = (random() % 94) + 32;
	testbuf[sizeof testbuf - 1] = '\0';
	assert(dkim_dstring_copy(dstring, testbuf));
	assert(dkim_dstring_len(dstring) == sizeof testbuf - 1);
	p = dkim_dstring_get(dstring);
	assert(p != NULL);
	assert(strlen(p) == sizeof testbuf - 1);
	assert(strcmp(p, testbuf) == 0);

	/* blank it */
	dkim_dstring_blank(dstring);
	p = dkim_dstring_get(dstring);
	assert(p != NULL);
	assert(p[0] == '\0');

	/* put something small in it using "cat" */
	assert(dkim_dstring_cat(dstring, TESTSTRING));
	p = dkim_dstring_get(dstring);
	assert(p != NULL);
	assert(strcmp(p, TESTSTRING) == 0);
	assert(dkim_dstring_cat(dstring, TESTSTRING));
	p = dkim_dstring_get(dstring);
	assert(p != NULL);
	assert(strcmp(p, TESTSTRING TESTSTRING) == 0);

	/* try cat1 */
	dkim_dstring_blank(dstring);
	assert(dkim_dstring_cat1(dstring, 'H'));
	assert(dkim_dstring_len(dstring) == 1);
	p = dkim_dstring_get(dstring);
	assert(p != NULL);
	assert(strcmp(p, "H") == 0);

	/* try catn */
	dkim_dstring_blank(dstring);
	assert(dkim_dstring_catn(dstring, TESTSTRING, 5));
	assert(dkim_dstring_len(dstring) == 5);
	p = dkim_dstring_get(dstring);
	assert(p != NULL);
	assert(strcmp(p, "Hello") == 0);

	/* start over */
	dkim_dstring_free(dstring);
	dstring = dkim_dstring_new(dkim, 0, (sizeof testbuf) / 2);
	assert(dstring != NULL);

	/* try an oversized append */
	assert(!dkim_dstring_copy(dstring, testbuf));

	/* clean up */
	dkim_dstring_free(dstring);
	dkim_free(dkim);
	dkim_close(lib);

	return 0;
}
