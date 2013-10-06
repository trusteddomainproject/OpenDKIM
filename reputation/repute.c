/*
**  Copyright (c) 2011-2013, The Trusted Domain Project.  All rights reserved.
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

#ifdef USE_JANSSON
/* libjansson includes */
# include <jansson.h>
#endif /* USE_JANSSON */

/* libcurl includes */
#include <curl/curl.h>

/* libut includes */
#include <ut.h>

/* librepute includes */
#include "repute.h"

/* limits */
#define	REPUTE_BUFBASE	1024
#define	REPUTE_URL	1024
#define	REPUTE_TIMEOUT	10

/* data types */
struct repute_io
{
	CURLcode		repute_errcode;
	unsigned int		repute_rcode;
	size_t			repute_alloc;
	size_t			repute_offset;
	char *			repute_buf;
	struct repute_io *	repute_next;
	CURL *			repute_curl;
};

struct repute_handle
{
	unsigned int		rep_reporter;
	pthread_mutex_t		rep_lock;
	struct repute_io *	rep_ios;
	const char *		rep_server;
	const char *		rep_useragent;
	const char *		rep_curlversion;
	char			rep_uritemp[REPUTE_URL + 1];
	char			rep_error[REPUTE_BUFBASE + 1];
};

/* globals */
static long timeout = REPUTE_TIMEOUT;

/*
**  REPUTE_CURL_WRITEDATA -- callback for libcurl to deliver data
**
**  Parameters:
**  	ptr -- pointer to the retrieved data
**  	size -- unit size
**  	nmemb -- unit count
**  	userdata -- opaque userdata (points to a repute_io structure)
**
**  Return value:
**  	Number of bytes taken in.  If different from "size", libcurl reports
**  	an error.
*/

static size_t
repute_curl_writedata(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	size_t need;
	struct repute_io *io;

	io = userdata;

	need = size * nmemb;

	if (io->repute_buf == NULL)
	{
		io->repute_alloc = MAX(REPUTE_BUFBASE, need);
		io->repute_buf = malloc(io->repute_alloc);
		if (io->repute_buf == NULL)
			return 0;
		memset(io->repute_buf, '\0', io->repute_alloc);
	}
	else if (io->repute_offset + need > io->repute_alloc)
	{
		size_t newsize;
		char *newbuf;

		newsize = MAX(io->repute_alloc * 2, io->repute_alloc + need);
		newbuf = realloc(io->repute_buf, newsize);
		if (newbuf == NULL)
		{
			return 0;
		}
		else
		{
			memset(newbuf + io->repute_offset, '\0',
			       newsize - io->repute_offset);
		}
		io->repute_buf = newbuf;
		io->repute_alloc = newsize;
	}

	memcpy(io->repute_buf + io->repute_offset, ptr, need);

	io->repute_offset += need;

	return need;
}

/*
**  REPUTE_PARSE -- parse a REPUTE message
**
**  Parameters:
**  	buf -- buffer containing a REPUTE reply
**  	rep -- returned reputation
**  	conf -- confidence
**  	sample -- sample size
**  	limit -- recommented flow limit
**  	when -- timestamp on the report
**
**  Return value:
**  	A REPUTE_STAT_* constant.
*/

static REPUTE_STAT
repute_parse(const char *buf, size_t buflen, float *rep, float *conf,
             unsigned long *sample, unsigned long *limit, time_t *when)
{
	_Bool found_dkim = FALSE;
	_Bool found_spam = FALSE;
	_Bool found_appl = FALSE;
	int code;
	float conftmp;
	float reptmp;
	unsigned long sampletmp;
	unsigned long limittmp;
	time_t whentmp;
	char *p;
	const char *start;
#ifdef USE_JANSSON
	json_t *root = NULL;
	json_t *obj = NULL;
	json_t *reps = NULL;
	json_error_t error;
#endif /* USE_JANSSON */

	assert(buf != NULL);
	assert(rep != NULL);

	/* skip any header found */
	/* XXX -- this should verify a desirable Content-Type */
	for (start = buf; *start != '\0'; start++)
	{
		if (*start == '\n' && *(start + 1) == '\n')
		{
			buflen = buflen - (start - buf + 2);
			buf = start + 2;
			break;
		}
		else if (*start == '\r' &&
		         *(start + 1) == '\n' &&
		         *(start + 2) == '\r' &&
		         *(start + 3) == '\n')
		{
			buflen = buflen - (start - buf + 4);
			buf = start + 4;
			break;
		}
	}

#ifdef USE_JANSSON
	root = json_loads(buf, 0, &error);
	if (root == NULL)
		return REPUTE_STAT_PARSE;

	obj = json_object_get(root, REPUTE_APPLICATION);
	if (obj != NULL && json_is_string(obj) &&
	    strcasecmp(json_string_value(obj), REPUTE_APPLICATION_VAL) == 0)
		found_appl = TRUE;

	reps = json_object_get(root, REPUTE_REPUTONS);
	if (reps != NULL && json_is_array(reps)) {
		int n;
		json_t *rep;

		for (n = 0; n < json_array_size(reps); n++) {
			rep = json_array_get(reps, n);

			obj = json_object_get(rep, REPUTE_ASSERTION);
			if (obj != NULL && json_is_string(obj) &&
			    strcasecmp(json_string_value(obj),
			               REPUTE_ASSERT_SPAM) == 0)
				found_spam = TRUE;

			obj = json_object_get(rep, REPUTE_EXT_IDENTITY);
			if (obj != NULL && json_is_string(obj) &&
			    strcasecmp(json_string_value(obj),
			               REPUTE_ID_DKIM) == 0)
				found_dkim = TRUE;

			obj = json_object_get(rep, REPUTE_EXT_RATE);
			if (obj != NULL && json_is_number(obj))
				limittmp = (unsigned long) json_integer_value(obj);

			obj = json_object_get(rep, REPUTE_CONFIDENCE);
			if (obj != NULL && json_is_number(obj))
				conftmp = (float) json_real_value(obj);

			obj = json_object_get(rep, REPUTE_RATING);
			if (obj != NULL && json_is_number(obj))
				reptmp = (float) json_real_value(obj);

			obj = json_object_get(rep, REPUTE_SAMPLE_SIZE);
			if (obj != NULL && json_is_number(obj))
				sampletmp = (unsigned long) json_integer_value(obj);

			obj = json_object_get(rep, REPUTE_GENERATED);
			if (obj != NULL && json_is_number(obj))
				whentmp = (time_t) json_integer_value(obj);
		}
	}

	if (found_appl && found_dkim && found_spam)
	{
		*rep = reptmp;
		if (conf != NULL)
			*conf = conftmp;
		if (sample != NULL)
			*sample = sampletmp;
		if (when != NULL)
			*when = whentmp;
		if (limit != NULL)
			*limit = limittmp;
	}

	json_decref(root);
#endif /* USE_JANSSON */

	return REPUTE_STAT_OK;
}

/*
**  REPUTE_GET_IO -- get or create an I/O handle
**
**  Parameters:
**  	rep -- REPUTE handle
**
**  Return value:
**  	An I/O handle if one could be either recycled or created, or NULL
**  	on failure.
*/

static struct repute_io *
repute_get_io(REPUTE rep)
{
	assert(rep != NULL);

	struct repute_io *rio = NULL;

	pthread_mutex_lock(&rep->rep_lock);

	if (rep->rep_ios != NULL)
	{
		rio = rep->rep_ios;

		rep->rep_ios = rep->rep_ios->repute_next;

		rio->repute_offset = 0;
	}
	else
	{
		rio = malloc(sizeof *rio);
		if (rio != NULL)
		{
			rio->repute_alloc = 0;
			rio->repute_offset = 0;
			rio->repute_buf = NULL;
			rio->repute_next = NULL;

			rio->repute_curl = curl_easy_init();
			if (rio->repute_curl == NULL)
			{
				free(rio);
				rio = NULL;
			}
			else
			{
				int status;
				long longtmp;

				status = curl_easy_setopt(rio->repute_curl,
				                          CURLOPT_WRITEFUNCTION,
		                                          repute_curl_writedata);
				if (status != CURLE_OK)
				{
					free(rio);
					rio = NULL;
				}

				if (rep->rep_useragent != NULL)
				{
					(void) curl_easy_setopt(rio->repute_curl,
					                        CURLOPT_USERAGENT,
					                        rep->rep_useragent);
				}

				longtmp = 1;
				(void) curl_easy_setopt(rio->repute_curl,
				                        CURLOPT_NOSIGNAL,
				                        longtmp);

				(void) curl_easy_setopt(rio->repute_curl,
				                        CURLOPT_TIMEOUT,
				                        timeout);
			}
		}
	}

	pthread_mutex_unlock(&rep->rep_lock);

	return rio;
}

/*
**  REPUTE_PUT_IO -- recycle an I/O handle
**
**  Parameters:
**  	rep -- REPUTE handle
**  	rio -- REPUTE I/O handle to be recycled
**
**  Return value:
**  	None.
*/

static void
repute_put_io(REPUTE rep, struct repute_io *rio)
{
	assert(rep != NULL);
	assert(rio != NULL);

	pthread_mutex_lock(&rep->rep_lock);

	rio->repute_next = rep->rep_ios;
	rep->rep_ios = rio;

	pthread_mutex_unlock(&rep->rep_lock);
}

/*
**  REPUTE_DOQUERY -- execute a query
**
**  Parameters:
**
**  Return value:
**  	A REPUTE_STAT_* constant.
*/

static REPUTE_STAT
repute_doquery(struct repute_io *rio, const char *url)
{
	CURLcode cstatus;
	long rcode;

	assert(rio != NULL);
	assert(url != NULL);

	cstatus = curl_easy_setopt(rio->repute_curl, CURLOPT_WRITEDATA, rio);
	if (cstatus != CURLE_OK)
	{
		rio->repute_errcode = cstatus;
		return REPUTE_STAT_INTERNAL;
	}

	cstatus = curl_easy_setopt(rio->repute_curl, CURLOPT_URL, url);
	if (cstatus != CURLE_OK)
	{
		rio->repute_errcode = cstatus;
		return REPUTE_STAT_INTERNAL;
	}

	rio->repute_errcode = 0;
	rio->repute_rcode = 0;
	memset(rio->repute_buf, '\0', rio->repute_alloc);

	cstatus = curl_easy_perform(rio->repute_curl);
	if (cstatus != CURLE_OK)
	{
		rio->repute_errcode = cstatus;
		return REPUTE_STAT_QUERY;
	}

	cstatus = curl_easy_getinfo(rio->repute_curl, CURLINFO_RESPONSE_CODE,
	                            &rcode);
	if (rcode != 200)
		return REPUTE_STAT_QUERY;

	return REPUTE_STAT_OK;
}

/*
**  REPUTE_GET_ERROR -- retrieve an error string
**
**  Parameters:
**  	rio -- repute I/O handle where an error occurred
**  	buf -- buffer to which to write the error string
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	None.
*/

static void
repute_get_error(struct repute_io *rio, char *buf, size_t buflen)
{
	assert(rio != NULL);
	assert(buf != NULL);

	if (rio->repute_rcode != 0)
		snprintf(buf, buflen, "HTTP error code %u", rio->repute_rcode);
	else
#ifdef HAVE_CURL_EASY_STRERROR
		snprintf(buf, buflen, curl_easy_strerror(rio->repute_errcode));
#else /* HAVE_CURL_EASY_STRERROR */
	{
		snprintf(buf, buflen, "CURL error code %u",
		         rio->repute_errcode);
	}
#endif /* HAVE_CURL_EASY_STRERROR */
}

/*
**  REPUTE_GET_TEMPLATE -- retrieve a URI template for a service
**
**  Parameters:
**  	rep -- REPUTE handle
**  	buf -- buffer into which to write the retrieved template
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A REPUTE_STAT_* constant.
*/

static int
repute_get_template(REPUTE rep)
{
	int cstatus;
	long rcode;
	struct repute_io *rio;
	URITEMP ut;
	char url[REPUTE_BUFBASE + 1];

	assert(rep != NULL);

	ut = ut_init();
	if (ut == NULL)
		return REPUTE_STAT_INTERNAL;

	if (ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "scheme", REPUTE_URI_SCHEME) != 0 ||
	    ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "service", (void *) rep->rep_server) != 0 ||
	    ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "application", REPUTE_URI_APPLICATION) != 0)
	{
		ut_destroy(ut);
		return REPUTE_STAT_INTERNAL;
	}

	if (ut_generate(ut, REPUTE_URI_TEMPLATE, url, sizeof url) <= 0)
	{
		ut_destroy(ut);
		return REPUTE_STAT_INTERNAL;
	}

	ut_destroy(ut);

	rio = repute_get_io(rep);
	if (rio == NULL)
		return REPUTE_STAT_INTERNAL;

	cstatus = curl_easy_setopt(rio->repute_curl, CURLOPT_WRITEDATA, rio);
	if (cstatus != CURLE_OK)
	{
#ifdef HAVE_CURL_EASY_STRERROR
		snprintf(rep->rep_error, sizeof rep->rep_error, "%s",
		         curl_easy_strerror(cstatus));
#else /* HAVE_CURL_EASY_STRERROR */
		snprintf(rep->rep_error, sizeof rep->rep_error,
		         "CURL error code %d", cstatus);
#endif /* HAVE_CURL_EASY_STRERROR */
		repute_put_io(rep, rio);
		return REPUTE_STAT_INTERNAL;
	}

	cstatus = curl_easy_setopt(rio->repute_curl, CURLOPT_URL, url);
	if (cstatus != CURLE_OK)
	{
#ifdef HAVE_CURL_EASY_STRERROR
		snprintf(rep->rep_error, sizeof rep->rep_error, "%s",
		         curl_easy_strerror(cstatus));
#else /* HAVE_CURL_EASY_STRERROR */
		snprintf(rep->rep_error, sizeof rep->rep_error,
		         "CURL error code %d", cstatus);
#endif /* HAVE_CURL_EASY_STRERROR */
		repute_put_io(rep, rio);
		return REPUTE_STAT_INTERNAL;
	}

	cstatus = curl_easy_perform(rio->repute_curl);
	if (cstatus != CURLE_OK)
	{
#ifdef HAVE_CURL_EASY_STRERROR
		snprintf(rep->rep_error, sizeof rep->rep_error, "%s",
		         curl_easy_strerror(cstatus));
#else /* HAVE_CURL_EASY_STRERROR */
		snprintf(rep->rep_error, sizeof rep->rep_error,
		         "CURL error code %d", cstatus);
#endif /* HAVE_CURL_EASY_STRERROR */
		repute_put_io(rep, rio);
		return REPUTE_STAT_QUERY;
	}

	cstatus = curl_easy_getinfo(rio->repute_curl, CURLINFO_RESPONSE_CODE,
	                            &rcode);
	if (rcode != 200)
	{
		snprintf(rep->rep_error, sizeof rep->rep_error,
		         "HTTP response code %u", (unsigned int) rcode);
		repute_put_io(rep, rio);
		return REPUTE_STAT_QUERY;
	}

	(void) snprintf(rep->rep_uritemp, sizeof rep->rep_uritemp, "%s",
	                rio->repute_buf);
	if (rep->rep_uritemp[rio->repute_offset - 1] == '\n')
		rep->rep_uritemp[rio->repute_offset - 1] = '\0';

	repute_put_io(rep, rio);

	return REPUTE_STAT_OK;
}

/*
**  REPUTE_INIT -- initialize REPUTE subsystem
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
repute_init(void)
{
	curl_global_init(CURL_GLOBAL_ALL);
}

/*
**  REPUTE_NEW -- make a new REPUTE handle
**
**  Parameters:
**  	server -- server hostname
**  	reporter -- reporter ID to use
**
**  Return value:
**  	A new REPUTE handle on success, NULL on failure.
*/

REPUTE
repute_new(const char *server, unsigned int reporter)
{
	struct repute_handle *new;
	curl_version_info_data *vinfo;

	assert(server != NULL);

	new = malloc(sizeof *new);
	if (new == NULL)
		return NULL;

	memset(new, '\0', sizeof *new);

	new->rep_reporter = reporter;
	new->rep_server = strdup(server);
	if (new->rep_server == NULL)
	{
		free(new);
		return NULL;
	}

	vinfo = curl_version_info(CURLVERSION_NOW);
	if (vinfo != NULL && vinfo->version != NULL)
		new->rep_curlversion = strdup(vinfo->version);

	pthread_mutex_init(&new->rep_lock, NULL);

	return new;
}

/*
**  REPUTE_CLOSE -- tear down a REPUTE handle
**
**  Paramters:
**  	rep -- REPUTE handle to shut down
**
**  Return value:
**  	None.
*/

void
repute_close(REPUTE rep)
{
	struct repute_io *rio;
	struct repute_io *next;

	assert(rep != NULL);

	rio = rep->rep_ios;
	while (rio != NULL)
	{
		next = rio->repute_next;

		if (rio->repute_buf != NULL)
			free(rio->repute_buf);
		if (rio->repute_curl != NULL)
			curl_easy_cleanup(rio->repute_curl);
		free(rio);

		rio = next;
	}

	pthread_mutex_destroy(&rep->rep_lock);

	free((void *) rep->rep_server);

	free(rep);
}

/*
**  REPUTE_CURLVERSION -- get libcurl version string
**
**  Parameters:
**  	rep -- REPUTE handle
**
**  Return value:
**  	A pointer to a string containing the libcurl version, or NULL.
*/

const char *
repute_curlversion(REPUTE rep)
{
	assert(rep != NULL);

	return rep->rep_curlversion;
}

/*
**  REPUTE_USERAGENT -- set user agent for REPUTE queries
**
**  Parameters:
**  	rep -- REPUTE handle
**  	ua -- User-Agent string to use
**
**  Return value:
**  	None.
*/

void
repute_useragent(REPUTE rep, const char *ua)
{
	if (rep->rep_useragent != NULL)
		free((void *) rep->rep_useragent);

	rep->rep_useragent = strdup(ua);
}

/*
**  REPUTE_QUERY -- query a REPUTE server for a spam reputation
**
**  Parameters:
**  	rep -- REPUTE handle
**  	domain -- domain of interest
**  	repout -- reputation (returned)
**  	confout -- confidence (returned)
**  	sampout -- sample count (returned)
**  	limitout -- limit (returned)
**  	whenout -- update timestamp (returned)
**
**  Return value:
**  	A REPUTE_STAT_* constant.
*/

REPUTE_STAT
repute_query(REPUTE rep, const char *domain, float *repout,
             float *confout, unsigned long *sampout, unsigned long *limitout,
             time_t *whenout)
{
	REPUTE_STAT status;
	float conf;
	float reputation;
	unsigned long samples;
	unsigned long limit;
	time_t when;
	struct repute_io *rio;
	URITEMP ut;
	char genurl[REPUTE_URL];

	assert(rep != NULL);
	assert(domain != NULL);
	assert(repout != NULL);

	if (rep->rep_uritemp[0] == '\0')
	{
		if (repute_get_template(rep) != REPUTE_STAT_OK)
			return REPUTE_STAT_QUERY;
	}

	ut = ut_init();
	if (ut == NULL)
		return REPUTE_STAT_INTERNAL;

	if (rep->rep_reporter != 0)
	{
		snprintf(genurl, sizeof genurl, "%u", rep->rep_reporter);
		if (ut_keyvalue(ut, UT_KEYTYPE_STRING,
		                "reporter", genurl) != 0)
		{
			ut_destroy(ut);
			return REPUTE_STAT_INTERNAL;
		}
	}

	if (ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "subject", (void *) domain) != 0 ||
#ifdef USE_JANSSON
	    ut_keyvalue(ut, UT_KEYTYPE_STRING, "format", "json") != 0 ||
#endif /* USE_JANSSON */
	    ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "scheme", REPUTE_URI_SCHEME) != 0 ||
	    ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "service", (void *) rep->rep_server) != 0 ||
	    ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "application", REPUTE_URI_APPLICATION) != 0 ||
	    ut_keyvalue(ut, UT_KEYTYPE_STRING,
	                "assertion", REPUTE_ASSERT_SPAM) != 0)
	{
		ut_destroy(ut);
		return REPUTE_STAT_INTERNAL;
	}

	if (ut_generate(ut, rep->rep_uritemp, genurl, sizeof genurl) <= 0)
	{
		ut_destroy(ut);
		return REPUTE_STAT_INTERNAL;
	}

	ut_destroy(ut);

	rio = repute_get_io(rep);
	if (rio == NULL)
		return REPUTE_STAT_INTERNAL;

	status = repute_doquery(rio, genurl);
	if (status != REPUTE_STAT_OK)
	{
		repute_get_error(rio, rep->rep_error, sizeof rep->rep_error);
		repute_put_io(rep, rio);
		return status;
	}

	status = repute_parse(rio->repute_buf, rio->repute_offset,
	                      &reputation, &conf, &samples, &limit, &when);
	if (status != REPUTE_STAT_OK)
	{
		snprintf(rep->rep_error, sizeof rep->rep_error,
		         "error parsing reply");
		repute_put_io(rep, rio);
		return status;
	}

	*repout = reputation;
	if (confout != NULL)
		*confout = conf;
	if (sampout != NULL)
		*sampout = samples;
	if (whenout != NULL)
		*whenout = when;
	if (limitout != NULL)
		*limitout = limit;

	repute_put_io(rep, rio);

	return REPUTE_STAT_OK;
}

/*
**  REPUTE_ERROR -- return a pointer to the error buffer
**
**  Parameters:
**  	rep -- REPUTE handle
**
**  Return value:
**  	Pointer to the error buffer inside the REPUTE handle.
*/

const char *
repute_error(REPUTE rep)
{
	assert(rep != NULL);

	return rep->rep_error;
}

/*
**  REPUTE_SET_TIMEOUT -- set REPUTE query timeout
**
**  Parameters:
**  	t -- timeout, in seconds
**
**  Return value:
**  	None.
*/

void
repute_set_timeout(long t)
{
	timeout = t;
}
