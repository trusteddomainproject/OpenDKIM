/*
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* librrd includes */
#include <rrd.h>

/* libreprrd includes */
#include "reprrd.h"

/* data types */
struct reprrd_handle
{
	int			rep_hashdepth;
	const char *		rep_root;
};

/*
**  REPRRD_TYPE -- translate a type code to a string
**
**  Parameters:
**  	code -- a REPRRD_TYPE_* constant
**
**  Return value:
**  	Pointer to a static string representation of "code".
*/

static const char *
reprrd_type(int code)
{
	switch (code)
	{
	  case REPRRD_TYPE_MESSAGES:
		return "messages";

	  case REPRRD_TYPE_SPAM:
		return "spam";

	  default:
		assert(0);
	}
}

/*
**  REPRRD_INIT -- initialize a reputation RRD context
**
**  Parameters:
**  	root -- root of the RRD directory tree
**  	hashdepth -- hashing depth in use
**
**  Return value:
**  	A REPRRD object, used to launch future queries.
*/

REPRRD
reprrd_init(const char *root, int hashdepth)
{
	REPRRD new;

	assert(root != NULL);

	new = (REPRRD) malloc(sizeof(struct reprrd_handle));
	if (new != NULL)
	{
		new->rep_hashdepth = hashdepth;

		new->rep_root = strdup(root);
		if (new->rep_root == NULL)
		{
			free(new);
			new = NULL;
		}
	}

	return new;
}

/*
**  REPRRD_CLOSE -- destroy a reputation RRD context
**
**  Parameters:
**  	r -- context to destroy
**
**  Return value:
**  	None.
*/

void
reprrd_close(REPRRD r)
{
	assert(r != NULL);

	free((void *) r->rep_root);
	free(r);
}

/*
**  REPRRD_QUERY -- query a reputaton parameter for a domain
**
**  Parameters:
**  	r -- REPRRD handle (query context)
**  	domain -- domain of interest
**  	type -- type of query (a REPRRD_TYPE_* constant)
** 	value -- current value (returned)
**  	err -- error buffer
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	A REPRRD_STAT_* constant.
*/

REPRRD_STAT
reprrd_query(REPRRD r, const char *domain, int type, int *value,
             char *err, size_t errlen)
{
	int c;
	int di;
	int status;
	size_t len;
	time_t start;
	time_t end;
	time_t step;
	time_t ti;
	u_long ds_cnt;
	char *p;
	char **ds_names;
	char **last_ds;
	rrd_value_t *data;
	char path[MAXPATHLEN + 1];

	assert(r != NULL);
	assert(domain != NULL);
	assert(value != NULL);
	assert(type == REPRRD_TYPE_MESSAGES || type == REPRRD_TYPE_SPAM);

	snprintf(path, sizeof path, "%s/%s", r->rep_root, reprrd_type(type));
	for (c = 0; c < r->rep_hashdepth; c++)
	{
		len = strlcat(path, "/", sizeof path - 1);
		if (len >= sizeof path - 1)
			return REPRRD_STAT_INTERNAL;
		path[len] = domain[c];
	}

	(void) strlcat(path, "/", sizeof path);
	len = strlcat(path, domain, sizeof path);
	if (len >= sizeof path)
		return REPRRD_STAT_INTERNAL;

	(void) time(&start);

	end = start;
	start -= REPRRD_STEP * REPRRD_BACKSTEPS;
	step = REPRRD_STEP;
	
	status = rrd_fetch_r(path, REPRRD_CF, &start, &end, &step, &ds_cnt,
	                     &ds_names, &data);
	if (status != 0)
		return REPRRD_STAT_QUERY;

	di = 0;

	for (ti = start + step; ti <= end; ti += step)
	{
		for (c = 0; c < ds_cnt; c++)
		{
			if (data[di++] == (rrd_value_t) 1.0)
				*value = 1;
		}
	}

        for (c = 0; c < ds_cnt; c++)
		free(ds_names[c]);
	free(ds_names);
	free(data);

	return REPRRD_STAT_OK;
}
