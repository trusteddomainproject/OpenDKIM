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
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define BADKEY		"-----BEGIN RSA PRIVATE KEY-----" \
	"MIICXQIBAAKBgQC4GUGr*d/6SFNzVLYpphnRd0QPGKz2uWnV65RAxa1Pw352Bqiz" \
	"qiKOBjgYGzj8pJQSs8tOvv/2k6jpI809RnESqOFgF0gu3UJbNnu3+cd8k/kiQj+q" \
	"4cKKRpAT92ccxc7svhCNgN1sBGmROYZuysG3Vu3Dyc079gSLtnSrgXb+gQIDAQAB" \
	"AoGAemlI0opm1Kvs2T4VliH8/tvX5FXbBH8LEZQAUwVeFTB/UQlieXyCV39pIxZO" \
	"0Sa50qm8YNL9rb5HTSZiHQFOwyAKNqS4m/7JCsbuH4gQkPgPF561BHNL9oKfYgJq" \
	"9P4kEFfDTBoXKBMxwWtT7AKV8dYvCa3vYzPQ/1BnqQdw2zECQQDyscdgR9Ih59PQ" \
	"b72ddibdsxS65uXS2vzYLe7SKl+4R5JgJzw0M6DTAnoYFf6JAsKGZM15PCC0E16t" \
	"RRo47U9VAkEAwjEVrlQ0/8yPACbDggDJg/Zz/uRu1wK0zjqj4vKjleubaX4SEvj7" \
	"r6xxZm9hC1pMJAC9y3bbkbgCRBjXfyY6fQJBANe5aq2MaZ41wTOPf45NjbKXEiAo" \
	"SbUpboKCIbyyaa8V/2h0t7D3C0dE9l4efsguqdZoF7Rh2/f1F70QpYRgfJkCQQCH" \
	"oRrAeGXP50JVW72fNgeJGH/pnghgOa6of0JpxwhENJuGMZxUDfxTtUA6yD3iXP3j" \
	"A3WL/wbaHsfOYf9Y+g1NAkAGLhx67Ah+uBNK4Xvfz0YPGINX20m+CMsxAw7FOaNv" \
	"IW2oWFfZCB4APkIis79Ql45AHpavwx5XodBMzZwJUvlL\n" \
	"-----END RSA PRIVATE KEY-----\n"

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
	uint64_t fixed_time;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];

	printf("*** signing attempt with an invalid key\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

#ifdef TEST_KEEP_FILES
	/* set flags */
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	key = BADKEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_RSASHA1, -1L, &status);
	assert(dkim != NULL);

	/* fix signing time */
	fixed_time = 1172620939;
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
	                    &fixed_time, sizeof fixed_time);

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
	assert(status == DKIM_STAT_NORESOURCE);

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	assert(status == DKIM_STAT_INVALID);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
