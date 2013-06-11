/*
**  Copyright (c) 2012, 2013, The Trusted Domain Project.  All rights reserved.
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
#include <math.h>

/* librrd includes */
#include <rrd.h>

/* libreprrd includes */
#include "reprrd.h"

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

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
**  REPRRD_MKPATH -- generate path to an RRD table
**
**  Parameters:
**  	path -- path buffer
**  	pathlen -- size of path buffer
**  	r -- REPRRD context
**  	domain -- domain to query
**  	type -- table type
**
**  Return value:
**  	A REPRRD_STAT_* constant.
*/

static REPRRD_STAT
reprrd_mkpath(char *path, size_t pathlen, REPRRD r, const char *domain,
              int type)
{
	int c;
	size_t len;

	assert(path != NULL);
	assert(pathlen > 0);
	assert(r != NULL);
	assert(domain != NULL);
	assert(type == REPRRD_TYPE_MESSAGES || type == REPRRD_TYPE_SPAM);

	snprintf(path, pathlen, "%s/%s", r->rep_root, reprrd_type(type));
	for (c = 0; c < r->rep_hashdepth; c++)
	{
		len = strlcat(path, "/", pathlen);
		if (len >= pathlen)
			return REPRRD_STAT_INTERNAL;
		path[len] = domain[c];
		path[len + 1] = '\0';
	}

	(void) strlcat(path, "/", pathlen);
	len = strlcat(path, domain, pathlen);
	if (len >= pathlen)
		return REPRRD_STAT_INTERNAL;
	else
		return REPRRD_STAT_OK;
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
	time_t start;
	time_t end;
	unsigned long step;
	time_t ti;
	time_t now;
	u_long ds_cnt;
	char **ds_names;
	char **cdata;
	rrd_value_t *data;
	rrd_value_t d_flow;			/* expected flow deviation */
	rrd_value_t d_spam;			/* expected spam deviation */
	rrd_value_t a_flow;			/* average flow */
	rrd_value_t a_spam;			/* average spam */
	rrd_value_t p_flow;			/* predicted flow */
	rrd_value_t p_spam;			/* predicted spam */
	rrd_value_t r_flow;			/* restricted flow */
	rrd_value_t l_flow;			/* last flow */
	char path[MAXPATHLEN + 1];

	assert(r != NULL);
	assert(domain != NULL);
	assert(value != NULL);
	assert(type == REPRRD_TYPE_MESSAGES || type == REPRRD_TYPE_SPAM ||
	       type == REPRRD_TYPE_LIMIT);

	(void) time(&now);

	if (type == REPRRD_TYPE_LIMIT)
	{
		time_t last_update;

		/* retrieve the most recent flow data */
		reprrd_mkpath(path, sizeof path, r, domain,
		              REPRRD_TYPE_MESSAGES);

		rrd_clear_error();
		status = rrd_lastupdate_r(path, &last_update, &ds_cnt,
		                          &ds_names, &cdata);
		if (status != 0)
		{
			return (errno == ENOENT ? REPRRD_STAT_NODATA
			                        : REPRRD_STAT_QUERY);
		}

		di = 0;

		l_flow = NAN;
		for (c = 0; c < ds_cnt; c++)
		{
			if (cdata[di] == cdata[di])
				l_flow = atof(cdata[di]);
			free(cdata[di++]);
		}

		for (c = 0; c < ds_cnt; c++)
			free(ds_names[c]);
		free(ds_names);
		free(cdata);

		if (l_flow != l_flow)
			return REPRRD_STAT_QUERY;

		/*
		**  Retrieve the predicted flow, which is the average plus
		**  twice the predicted deviation.
		*/

		end = now;
		start = last_update - 1;
		step = REPRRD_STEP;
	
		reprrd_mkpath(path, sizeof path, r, domain,
		              REPRRD_TYPE_MESSAGES);

		rrd_clear_error();
		status = rrd_fetch_r(path, REPRRD_CF_HWPREDICT, &start, &end,
		                     &step, &ds_cnt, &ds_names, &data);
		if (status != 0)
		{
			return (errno == ENOENT ? REPRRD_STAT_NODATA
			                        : REPRRD_STAT_QUERY);
		}

		di = 0;

		d_flow = NAN;
		for (ti = start + step; ti <= end; ti += step)
		{
			for (c = 0; c < ds_cnt; c++)
			{
				if (data[di] == data[di])
					d_flow = data[di];
				di++;
			}
		}

		for (c = 0; c < ds_cnt; c++)
			free(ds_names[c]);
		free(ds_names);
		free(data);

		if (d_flow != d_flow)
			return REPRRD_STAT_QUERY;

		end = now;
		start = last_update - 1;
		step = REPRRD_STEP;
	
		rrd_clear_error();
		status = rrd_fetch_r(path, REPRRD_CF_AVERAGE, &start, &end,
		                     &step, &ds_cnt, &ds_names, &data);
		if (status != 0)
		{
			return (errno == ENOENT ? REPRRD_STAT_NODATA
			                        : REPRRD_STAT_QUERY);
		}

		di = 0;

		a_flow = NAN;
		for (ti = start + step; ti <= end; ti += step)
		{
			for (c = 0; c < ds_cnt; c++)
			{
				if (data[di] == data[di])
					a_flow = data[di];
				di++;
			}
		}

		for (c = 0; c < ds_cnt; c++)
			free(ds_names[c]);
		free(ds_names);
		free(data);

		if (a_flow != a_flow)
			return REPRRD_STAT_QUERY;

		p_flow = a_flow + d_flow * 2.;

		/* retrieve the predicted spam ratio */
		end = now;
		start = last_update - 1;
		step = REPRRD_STEP;
	
		reprrd_mkpath(path, sizeof path, r, domain, REPRRD_TYPE_SPAM);

		rrd_clear_error();
		status = rrd_fetch_r(path, REPRRD_CF_HWPREDICT, &start, &end,
		                     &step, &ds_cnt, &ds_names, &data);
		if (status != 0)
		{
			return (errno == ENOENT ? REPRRD_STAT_NODATA
			                        : REPRRD_STAT_QUERY);
		}

		di = 0;

		d_spam = NAN;
		for (ti = start + step; ti <= end; ti += step)
		{
			for (c = 0; c < ds_cnt; c++)
			{
				if (data[di] == data[di])
					d_spam = data[di];
				di++;
			}
		}

		for (c = 0; c < ds_cnt; c++)
			free(ds_names[c]);
		free(ds_names);
		free(data);

		if (d_spam != d_spam)
			return REPRRD_STAT_QUERY;

		end = now;
		start = last_update - 1;
		step = REPRRD_STEP;

		rrd_clear_error();
		status = rrd_fetch_r(path, REPRRD_CF_AVERAGE, &start, &end,
		                     &step, &ds_cnt, &ds_names, &data);
		if (status != 0)
		{
			return (errno == ENOENT ? REPRRD_STAT_NODATA
			                        : REPRRD_STAT_QUERY);
		}

		di = 0;

		a_spam = NAN;
		for (ti = start + step; ti <= end; ti += step)
		{
			for (c = 0; c < ds_cnt; c++)
			{
				if (data[di] == data[di])
					a_spam = data[di];
				di++;
			}
		}

		for (c = 0; c < ds_cnt; c++)
			free(ds_names[c]);
		free(ds_names);
		free(data);

		if (a_spam != a_spam)
			return REPRRD_STAT_QUERY;

		/* prediction computation */
		p_spam = a_spam + d_spam * 2.;

		/* apply the limiting algorithm */
		r_flow = p_flow * (1. - p_spam);

		/* see if it's higher than expected */
		*value = (l_flow >= r_flow);
	}
	else
	{
		reprrd_mkpath(path, sizeof path, r, domain, type);

		end = now;
		start = now - REPRRD_STEP * REPRRD_BACKSTEPS;
		step = REPRRD_STEP;
	
		rrd_clear_error();
		status = rrd_fetch_r(path, REPRRD_CF_FAILURES, &start, &end,
		                     &step, &ds_cnt, &ds_names, &data);
		if (status != 0)
		{
			return (errno == ENOENT ? REPRRD_STAT_NODATA
			                        : REPRRD_STAT_QUERY);
		}

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
	}

	return REPRRD_STAT_OK;
}
