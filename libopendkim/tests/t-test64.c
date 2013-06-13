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

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG2 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="

struct malloc_track
{
	size_t			mt_size;
	void *			mt_ptr;
	struct malloc_track *	mt_next;
};

unsigned int mtsize;
unsigned int mtcount;
struct malloc_track *mtstack;

/*
**  DEBUG_INIT -- initialize tracking malloc() wrapper
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
debug_init(void)
{
	mtstack = NULL;
	mtsize = 0;
	mtcount = 0;
}

/*
**  DEBUG_MALLOC -- tracking malloc() wrapper
**
**  Parameters:
**  	closure -- memory closure (not used)
**  	nbytes -- how many bytes to get
**
**  Return value:
**  	Pointer to allocated memory.
*/

void *
debug_malloc(void *closure, size_t nbytes)
{
	struct malloc_track *new;
	void *ptr;

	assert(nbytes > 0);

	new = (void *) malloc(sizeof(struct malloc_track));
	if (new == NULL)
		return NULL;

	ptr = (void *) malloc(nbytes);
	if (new == NULL)
		return NULL;

	new->mt_next = mtstack;
	new->mt_ptr = ptr;
	new->mt_size = nbytes;
	mtstack = new;
	mtsize++;
	mtcount++;

	return ptr;
}

/*
**  DEBUG_FREE -- tracking wrapper for free()
**
**  Parameters:
**  	closure -- memory closure (not used)
**  	ptr -- pointer to free
**
**  Return value:
**  	None.
*/

void
debug_free(void *closure, void *ptr)
{
	struct malloc_track *mt;
	struct malloc_track *last;

	assert(ptr != NULL);
	assert(mtstack != NULL);

	mt = mtstack;
	last = NULL;
	while (mt != NULL)
	{
		if (mt->mt_ptr == ptr)
		{
			if (mt == mtstack)
				mtstack = mt->mt_next;
			else
				last->mt_next = mt->mt_next;

			free(mt);
			free(ptr);
			mtsize--;
			return;
		}

		last = mt;
		mt = mt->mt_next;
	}

	assert(0);
}

/*
**  DEBUG_DUMP -- return contents of malloc tracking
**
**  Parameters:
**  	out -- stream to which to write
**
**  Return value:
**  	None.
*/

void
debug_dump(FILE *out)
{
	struct malloc_track *mt;

	assert(out != NULL);

	fprintf(out, "--- %u allocation(s) recorded\n", mtcount);

	if (mtstack != NULL)
	{
		fprintf(out, "--- %u dangling allocation(s):\n", mtsize);

		mt = mtstack;
		while (mt != NULL)
		{
			fprintf(out, "\t%p %lu\n", mt->mt_ptr,
			        (unsigned long) mt->mt_size);
			mt = mt->mt_next;
		}
	}
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
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char hdr[MAXHEADER + 1];

	printf("*** relaxed/simple rsa-sha1 verifying with leak detection\n");

	debug_init();

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(debug_malloc, debug_free);
	assert(lib != NULL);

#ifdef TEST_KEEP_FILES
	/* set flags */
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER01, strlen(HEADER01));
	assert(status == DKIM_STAT_OK);

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
	assert(status == DKIM_STAT_OK);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	debug_dump(stdout);
	assert(mtsize == 0);
	assert(mtstack == NULL);

	dkim_close(lib);

	return 0;
}
