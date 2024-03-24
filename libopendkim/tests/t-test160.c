/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2010-2014,2024 The Trusted Domain Project.
**  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"

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
	DKIM_STAT status;
	DKIM_ITER_CTX *ctx;
	const char *name_iter;
	int code_iter;
	const char *name_lookup;
	int code_lookup;

	printf("*** testing DKIM_NAMETABLE routines\n");

	/* assuming dkim_table_canonicalizations had only 2 entries */
	status = dkim_nametable_first(dkim_table_canonicalizations,
	                            &ctx, &name_iter, &code_iter);

	assert(status == DKIM_STAT_OK);

	code_lookup = dkim_name_to_code(dkim_table_canonicalizations,
	                                name_iter);

	assert(code_lookup == code_iter);

	name_lookup = dkim_code_to_name(dkim_table_canonicalizations,
	                                code_iter);

	assert(name_lookup == name_iter);

	status = dkim_nametable_next(ctx, &name_iter, &code_iter);

	assert(status == DKIM_STAT_OK);

	code_lookup = dkim_name_to_code(dkim_table_canonicalizations,
	                                name_iter);

	assert(code_lookup == code_iter);

	name_lookup = dkim_code_to_name(dkim_table_canonicalizations,
	                                code_iter);

	assert(name_lookup == name_iter);

	status = dkim_nametable_next(ctx, &name_iter, &code_iter);

	assert(status == DKIM_STAT_ITER_EOT);
	assert(code_lookup == code_iter);
	assert(name_lookup == name_iter);

	status = dkim_nametable_next(ctx, &name_iter, &code_iter);

	assert(status == DKIM_STAT_ITER_EOT);
	assert(code_lookup == code_iter);
	assert(name_lookup == name_iter);

	status = dkim_iter_ctx_free(ctx);

	assert(status == DKIM_STAT_OK);

	return 0;
}
