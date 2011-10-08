/*
**  Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char repute_c_id[] = "$Id$";
#endif /* ! lint */

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

/* libxml includes */
#include <libxml/parser.h>
#include <libxml/tree.h>

/* libcurl includes */
#include <curl/curl.h>

/* librepute includes */
#include "repute.h"

/* data types */
struct repute_io
{
	CURL *		repute_curl;
	size_t		repute_alloc;
	size_t		repute_len;
	size_t		repute_offset;
	char *		repute_buf;
	struct repute_io * repute_next;
};

struct repute_lookup
{
	int		rt_code;
	const char *	rt_name;
};

/* lookup tables */
struct repute_lookup repute_lookup_elements[] =
{
	{ REPUTE_XML_CODE_ASSERTION,	REPUTE_XML_ASSERTION },
	{ REPUTE_XML_CODE_EXTENSION,	REPUTE_XML_EXTENSION },
	{ REPUTE_XML_CODE_RATED,	REPUTE_XML_RATED },
	{ REPUTE_XML_CODE_RATER,	REPUTE_XML_RATER },
	{ REPUTE_XML_CODE_RATER_AUTH,	REPUTE_XML_RATER_AUTH },
	{ REPUTE_XML_CODE_RATING,	REPUTE_XML_RATING },
	{ REPUTE_XML_CODE_SAMPLE_SIZE,	REPUTE_XML_SAMPLE_SIZE },
	{ REPUTE_XML_CODE_UNKNOWN,	NULL }
};

/* globals */
static pthread_mutex_t rep_lock;
static struct repute_io *rep_ios = NULL;

/* limits */
#define	REPUTE_BUFBASE	1024
#define	REPUTE_URL	1024

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
	}
	else if (io->repute_len + need < io->repute_alloc)
	{
		size_t newsize;
		char *newbuf;

		newsize = MAX(io->repute_alloc * 2, io->repute_alloc + need);
		newbuf = realloc(io->repute_buf, newsize);
		if (newbuf == NULL)
			return 0;
		io->repute_buf = newbuf;
		io->repute_alloc = newsize;
	}

	memcpy(io->repute_buf + io->repute_offset, ptr, need);

	io->repute_offset += need;

	return need;
}

/*
**  REPUTE_NAME_TO_CODE -- look up a name in a table
**
**  Parameters:
**  	tbl -- table to search
**  	name -- name to find
**
**  Return value:
**  	Matching code.
*/

static int
repute_name_to_code(struct repute_lookup *tbl, const char *name)
{
	int c;

	assert(tbl != NULL);
	assert(name != NULL);

	for (c = 0; ; c++)
	{
		if (tbl[c].rt_name == NULL ||
		    strcasecmp(name, tbl[c].rt_name) == 0)
			return tbl[c].rt_code;
	}

	return -1;
}

/*
**  REPUTE_PARSE -- parse a REPUTE message
**
**  Parameters:
**  	buf -- buffer containing a REPUTE reply
**  	rep -- returned reputation
**  	conf -- confidence
**  	sample -- sample size
**
**  Return value:
**  	A REPUTE_STAT_* constant.
*/

static REPUTE_STAT
repute_parse(const char *buf, size_t buflen, float *rep, float *conf,
             unsigned long *sample)
{
	_Bool found_dkim = FALSE;
	_Bool found_spam = FALSE;
	int code;
	float conftmp;
	float reptmp;
	unsigned long sampletmp;
	char *p;
	xmlDocPtr doc = NULL;
	xmlNode *node = NULL;
	xmlNode *reputon = NULL;

	assert(buf != NULL);
	assert(rep != NULL);

	doc = xmlParseMemory(buf, buflen);
	if (doc == NULL)
		return REPUTE_STAT_PARSE;

	node = xmlDocGetRootElement(doc);
	if (node == NULL)
	{
		xmlFreeDoc(doc);
		return REPUTE_STAT_PARSE;
	}

	/* confirm root's name */
	if (node->name == NULL ||
	    strcasecmp(node->name, REPUTE_NAME_REPUTATION) != 0 ||
	    node->children == NULL)
	{
		xmlFreeDoc(doc);
		return REPUTE_STAT_PARSE;
	}

	/* iterate through reputons looking for the right report */
	for (node = node->children; node != NULL; node = node->next)
	{
		/* skip unnamed things or things that aren't reputons */
		if (node->name == NULL ||
		    strcasecmp(node->name, REPUTE_NAME_REPUTON) != 0 ||
		    node->children == NULL)
			continue;

		found_dkim = FALSE;
		found_spam = FALSE;
		conftmp = 0.;
		reptmp = 0.;
		sampletmp = 0L;

		for (reputon = node->children;
		     reputon != NULL;
		     reputon = reputon->next)
		{
			/* skip unnamed and empty things */
			if (reputon->name == NULL || reputon->content == NULL)
				continue;

			/* skip unknown names */
			code = repute_name_to_code(repute_lookup_elements,
			                           reputon->name);
			if (code == -1)
				continue;

			switch (code)
			{
			  case REPUTE_XML_CODE_RATER:
				/*
				**  We assume for now that we got an answer
				**  from the same place we asked.
				*/

				break;

			  case REPUTE_XML_CODE_RATER_AUTH:
				conftmp = strtof(reputon->content, &p);
				if (*p != '\0' || conftmp < 0 || conftmp > 1)
					continue;

			  case REPUTE_XML_CODE_ASSERTION:
				if (strcasecmp(reputon->content,
				               REPUTE_ASSERT_SENDS_SPAM) == 0)
					found_spam = TRUE;
				break;

			  case REPUTE_XML_CODE_EXTENSION:
				if (strcasecmp(reputon->content,
				               REPUTE_EXT_ID_DKIM) == 0)
					found_dkim = TRUE;
				break;

			  case REPUTE_XML_CODE_RATED:
				/*
				**  We assume for now that we got an answer
				**  to the right question.
				*/

				break;

			  case REPUTE_XML_CODE_RATING:
				reptmp = strtof(reputon->content, &p);
				if (*p != '\0' || reptmp < -1 || reptmp > 1)
					continue;

			  case REPUTE_XML_CODE_SAMPLE_SIZE:
				errno = 0;
				sampletmp = strtoul(reputon->content, &p, 10);
				if (errno != 0)
					continue;

			  default:
				break;
			}
		}

		if (found_dkim && found_spam)
		{
			*rep = reptmp;
			if (conf != NULL)
				*conf = conftmp;
			if (sample != NULL)
				*sample = sampletmp;

			break;
		}
	}

	xmlFreeDoc(doc);
	return REPUTE_STAT_OK;
}

/*
**  REPUTE_GET_IO -- get or create an I/O handle
**
**  Parameters:
**  	None.
**
**  Return value:
**  	An I/O handle if one could be either recycled or created, or NULL
**  	on failure.
*/

static struct repute_io *
repute_get_io(void)
{
	struct repute_io *rio = NULL;

	pthread_mutex_lock(&rep_lock);

	if (rep_ios != NULL)
	{
		rio = rep_ios;

		rep_ios = rep_ios->repute_next;

		rio->repute_len = 0;
		rio->repute_offset = 0;
	}
	else
	{
		rio = malloc(sizeof *rio);
		if (rio != NULL)
		{
			rio->repute_alloc = 0;
			rio->repute_len = 0;
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

				status = curl_easy_setopt(rio->repute_curl,
				                          CURLOPT_WRITEFUNCTION,
		                                          repute_curl_writedata);
				if (status != CURLE_OK)
				{
					free(rio);
					rio = NULL;
				}
			}
		}
	}

	pthread_mutex_unlock(&rep_lock);

	return rio;
}

/*
**  REPUTE_PUT_IO -- recycle an I/O handle
**
**  Parameters:
**  	rio -- REPUTE I/O handle to be recycled
**
**  Return value:
**  	None.
*/

static void
repute_put_io(struct repute_io *rio)
{
	assert(rio != NULL);

	pthread_mutex_lock(&rep_lock);

	rio->repute_next = rep_ios;
	rep_ios = rio;

	pthread_mutex_unlock(&rep_lock);
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

	assert(rio != NULL);
	assert(url != NULL);

	cstatus = curl_easy_setopt(rio->repute_curl, CURLOPT_WRITEDATA, rio);
	if (cstatus != CURLE_OK)
		return REPUTE_STAT_INTERNAL;

	cstatus = curl_easy_setopt(rio->repute_curl, CURLOPT_URL, url);
	if (cstatus != CURLE_OK)
		return REPUTE_STAT_INTERNAL;

	cstatus = curl_easy_perform(rio->repute_curl);
	if (cstatus != CURLE_OK)
		return REPUTE_STAT_QUERY;

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
	xmlInitParser();

	curl_global_init(CURL_GLOBAL_ALL);

	pthread_mutex_init(&rep_lock, NULL);

	rep_ios = NULL;
}

/*
**  REPUTE_CLOSE -- tear down REPUTE subsystem
**
**  Paramters:
**  	None.
**
**  Return value:
**  	None.
*/

void
repute_close(void)
{
	struct repute_io *rio;
	struct repute_io *next;

	rio = rep_ios;
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

	pthread_mutex_destroy(&rep_lock);
}

/*
**  REPUTE_QUERY -- query a REPUTE server for a spam reputation
**
**  Parameters:
**  	domain -- domain of interest
**  	server -- REPUTE server to query
**  	repout -- reputation (returned)
**  	confout -- confidence (returned)
**  	sampout -- sample count (returned)
**
**  Return value:
**  	A REPUTE_STAT_* constant.
*/

REPUTE_STAT
repute_query(const char *domain, const char *server, float *repout,
             float *confout, unsigned long *sampout)
{
	REPUTE_STAT status;
	float conf;
	float rep;
	unsigned long samples;
	struct repute_io *rio;
	char url[REPUTE_URL];

	assert(domain != NULL);
	assert(server != NULL);
	assert(repout != NULL);

	rio = repute_get_io();
	if (rio == NULL)
		return REPUTE_STAT_INTERNAL;

	snprintf(url, sizeof url, "%s://%s/%s/%s", REPUTE_URI_SCHEME,
	         server, REPUTE_URI_APPLICATION, domain);

	status = repute_doquery(rio, url);
	if (status != REPUTE_STAT_OK)
	{
		repute_put_io(rio);
		return status;
	}

	status = repute_parse(rio->repute_buf, rio->repute_offset,
	                      &rep, &conf, &samples);
	if (status != REPUTE_STAT_OK)
	{
		repute_put_io(rio);
		return status;
	}

	*repout = rep;
	if (confout != NULL)
		*confout = conf;
	if (sampout != NULL)
		*sampout = samples;

	repute_put_io(rio);

	return REPUTE_STAT_OK;
}
