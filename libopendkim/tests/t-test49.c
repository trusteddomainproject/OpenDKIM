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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* libdb includes */
#ifdef QUERY_CACHE
# include <db.h>
#endif /* QUERY_CACHE */

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "../dkim-cache.h"
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
	u_int s1, s2, s3, s4;
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
	dkim_cache_stats(cache, &s1, &s2, &s3, &s4, FALSE);
	assert(s1 == 3);
	assert(s2 == 1);
	assert(s3 == 1);
	assert(s4 == 0);

	dkim_cache_close(cache);
#endif /* ! QUERY_CACHE */

	return 0;
}
