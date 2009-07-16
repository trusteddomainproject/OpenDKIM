/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char t_test49_c_id[] = "@(#)$Id: t-test49.c,v 1.1 2009/07/16 19:12:04 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* libdb includes */
#ifdef QUERY_CACHE
# include <db.h>
#endif /* QUERY_CACHE */

/* libsm includes */
#include <sm/gen.h>

/* libdkim includes */
#include "dkim.h"
#include "dkim-cache.h"
#include "t-testdata.h"

#define	BUFRSZ	1024
#define	QUERY	"Test Key"
#define	DATA	"Cached Data"

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
#ifndef QUERY_CACHE
	printf("*** query caching SKIPPED\n");

#else /* ! QUERY_CACHE */

	int status;
	int err;
	u_int s1, s2, s3;
	size_t buflen;
	DB *cache;
	char buf[BUFRSZ + 1];

	printf("*** query caching\n");

	cache = dkim_cache_init(NULL, NULL);

	err = 0;

	printf("--- empty cache\n");
	buflen = sizeof buf;
	status = dkim_cache_query(cache, QUERY, 0, buf, &buflen, &err);
	assert(err == 0);
	assert(status == 1);

	printf("--- insert record\n");
	status = dkim_cache_insert(cache, QUERY, DATA, 3, &err);
	assert(err == 0);
	assert(status == 0);

	printf("--- retrieve record\n");
	memset(buf, '\0', sizeof buf);
	buflen = sizeof buf;
	status = dkim_cache_query(cache, QUERY, 0, buf, &buflen, &err);
	assert(err == 0);
	assert(status == 0);
	assert(buflen == strlen(DATA));
	assert(strcmp(buf, DATA) == 0);

	printf("--- [pause for record to expire]\n");
	sleep(4);

	printf("--- retrieve expired record\n");
	buflen = sizeof buf;
	status = dkim_cache_query(cache, QUERY, 0, buf, &buflen, &err);
	assert(err == 0);
	assert(status == 1);

	printf("--- expire old records\n");
	status = dkim_cache_expire(cache, 3, &err);
	assert(err == 0);
	assert(status == 1);

	printf("--- retrieve cache stats\n");
	dkim_cache_stats(&s1, &s2, &s3);
	assert(s1 == 3);
	assert(s2 == 1);
	assert(s3 == 1);

	dkim_cache_close(cache);
#endif /* ! QUERY_CACHE */

	return 0;
}
