/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-db.c,v 1.101.10.1 2010/10/27 21:43:09 cm-msk Exp $
*/

#ifndef lint
static char opendkim_db_c_id[] = "@(#)$Id: opendkim-db.c,v 1.101.10.1 2010/10/27 21:43:09 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! _REENTRANT */

/* system includes */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <regex.h>

/* libopendkim includes */
#include <dkim.h>
#include <dkim-strl.h>

/* opendkim includes */
#include "util.h"
#ifdef OPENDKIM_DB_ONLY
# undef USE_LDAP
# undef USE_SASL
# undef USE_ODBX
# undef USE_LUA
#endif /* OPENDKIM_DB_ONLY */
#include "opendkim-db.h"
#ifdef USE_LUA
# include "opendkim-lua.h"
#endif /* USE_LUA */

/* various DB library includes */
#ifdef USE_DB
# include <db.h>
#endif /* USE_DB */
#ifdef USE_ODBX
# include <odbx.h>
#endif /* USE_ODBX */
#ifdef USE_LDAP
# include <ldap.h>
#endif /* USE_LDAP */
#ifdef USE_SASL
# include <sasl/sasl.h>
#endif /* USE_SASL */
#ifdef USE_LUA
# include <lua.h>
#endif /* USE_LUA */

/* macros */
#define	BUFRSZ			1024
#define	DEFARRAYSZ		16
#define DKIMF_DB_MODE		0644
#define DKIMF_LDAP_MAXURIS	8
#define DKIMF_LDAP_TIMEOUT	5
#ifdef _FFR_LDAP_CACHING
# define DKIMF_LDAP_TTL		600
#endif /* _FFR_LDAP_CACHING */

#define	DKIMF_DB_IFLAG_FREEARRAY 0x01
#define	DKIMF_DB_IFLAG_RECONNECT 0x02

#ifndef FALSE
# define FALSE			0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE			1
#endif /* ! TRUE */

#ifndef MAX
# define MAX(x,y)	((x) > (y) ? (x) : (y))
#endif /* ! MAX */

#ifdef USE_DB
# ifndef DB_NOTFOUND
#  define DB_NOTFOUND		1
# endif /* ! DB_NOTFOUND */
# ifndef DB_VERSION_MAJOR
#  define DB_VERSION_MAJOR	1
# endif /* ! DB_VERSION_MAJOR */

# define DB_VERSION_CHECK(x,y,z) ((DB_VERSION_MAJOR == (x) && \
				   DB_VERSION_MINOR == (y) && \
				   DB_VERSION_PATCH >= (z)) || \
				  (DB_VERSION_MAJOR == (x) && \
				   DB_VERSION_MINOR > (y)) || \
				  DB_VERSION_MAJOR > (x))

# if DB_VERSION_CHECK(3,0,0)
#  define DB_STRERROR(x)	db_strerror(x)
# else /* DB_VERSION_CHECK(3,0,0) */
#  define DB_STRERROR(x)	strerror(errno)
# endif /* DB_VERSION_CHECK(3,0,0) */

# if DB_VERSION_MAJOR < 2
#  define DKIMF_DBCLOSE(db)	(db)->close((db))
# else /* DB_VERSION_MAJOR < 2 */
#  define DKIMF_DBCLOSE(db)	(db)->close((db), 0)
# endif /* DB_VERSION_MAJOR < 2 */
#endif /* USE_DB */

/* macros */
#ifndef MIN
# define MIN(x,y)       ((x) < (y) ? (x) : (y))
#endif /* ! MIN */

/* data types */
struct dkimf_db
{
	u_int			db_flags;
	u_int			db_iflags;
	u_int			db_type;
	int			db_status;
	int			db_nrecs;
	pthread_mutex_t *	db_lock;
	void *			db_handle;	/* handler handle */
	void *			db_data;	/* dkimf_db handle */
	void *			db_cursor;	/* cursor */
	void *			db_entry;	/* entry (context) */
	char **			db_array;
};

struct dkimf_db_table
{
	char *			name;
	int 			code;
};

struct dkimf_db_list
{
	char *			db_list_key;
	char *			db_list_value;
	struct dkimf_db_list *	db_list_next;
};

struct dkimf_db_relist
{
	regex_t			db_relist_re;
	char *			db_relist_data;
	struct dkimf_db_relist * db_relist_next;
};

#ifdef USE_ODBX
struct dkimf_db_dsn
{
	char			dsn_backend[BUFRSZ];
	char			dsn_datacol[BUFRSZ];
	char			dsn_dbase[BUFRSZ];
	char			dsn_host[BUFRSZ];
	char			dsn_keycol[BUFRSZ];
	char			dsn_password[BUFRSZ];
	char			dsn_port[BUFRSZ];
	char			dsn_table[BUFRSZ];
	char			dsn_user[BUFRSZ];
};
#endif /* USE_ODBX */

#ifdef USE_LDAP
struct dkimf_db_ldap
{
	int			ldap_timeout;
	char			ldap_urilist[BUFRSZ];
	LDAPURLDesc *		ldap_descr;
# ifdef _FFR_LDAP_CACHING
#  ifdef USE_DB
	DKIMF_DB		ldap_cache;
#  endif /* USE_DB */
# endif /* _FFR_LDAP_CACHING */
	pthread_mutex_t		ldap_lock;
};

# ifdef _FFR_LDAP_CACHING
#  ifdef USE_DB
#   define DKIMF_DB_CACHE_DATA		0
#   define DKIMF_DB_CACHE_PENDING	1
struct dkimf_db_ldap_cache
{
	_Bool			ldc_absent;
	int			ldc_state;
	int			ldc_nresults;
	int			ldc_waiters;
	int			ldc_error;
	time_t			ldc_expire;
	void *			ldc_handle;
	char **			ldc_results;
	pthread_cond_t		ldc_cond;
};
#  endif /* USE_DB */
# endif /* _FFR_LDAP_CACHING */
#endif /* USE_LDAP */

#ifdef USE_LUA
struct dkimf_db_lua
{
	char *			lua_script;
	char *			lua_error;
};
#endif /* USE_LUA */


/* globals */
struct dkimf_db_table dbtypes[] =
{
	{ "csl",		DKIMF_DB_TYPE_CSL },
	{ "file",		DKIMF_DB_TYPE_FILE },
	{ "refile",		DKIMF_DB_TYPE_REFILE },
#ifdef USE_DB
	{ "db",			DKIMF_DB_TYPE_BDB },
#endif /* USE_DB */
#ifdef USE_ODBX
	{ "dsn",		DKIMF_DB_TYPE_DSN },
#endif /* USE_ODBX */
#ifdef USE_LDAP
	{ "ldap",		DKIMF_DB_TYPE_LDAP },
	{ "ldapi",		DKIMF_DB_TYPE_LDAP },
	{ "ldaps",		DKIMF_DB_TYPE_LDAP },
#endif /* USE_LDAP */
#ifdef USE_LUA
	{ "lua",		DKIMF_DB_TYPE_LUA },
#endif /* USE_LUA */
	{ NULL,			DKIMF_DB_TYPE_UNKNOWN },
};

static char *dkimf_db_ldap_param[DKIMF_LDAP_PARAM_MAX + 1];

#if (USE_SASL && USE_LDAP)
/*
**  DKIMF_DB_SASLINTERACT -- SASL binding interaction callback
**
**  Parameters:
**  	ld -- LDAP handle (see below)
**  	flags -- LDAP handling flags
**  	defaults -- defaults pointer (see below)
**  	interact -- SASL interaction object
**
**  Return value:
**  	LDAP_SUCCESS (for now)
**
**  Notes:
**  	If SASL requires additional parameters that OpenLDAP didn't provide
**  	in its call, it uses a callback we have to provide to try to get them.
**  	The layering here can get quite confusing.  "defaults" is an
**  	application-specific handle that can point to a bunch of defaults
**  	set elsewhere, but we don't need it here so it's ignored.  Similarly,
**  	"ld" is not actually needed.
*/

static int
dkimf_db_saslinteract(LDAP *ld, unsigned int flags, void *defaults,
                      void *sasl_interact)
{
	sasl_interact_t *interact;

	assert(sasl_interact != NULL);

	interact = sasl_interact;

	switch (interact->id)
	{
	  case SASL_CB_PASS:
		interact->result = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_BINDPW];
		interact->len = strlen(interact->result);
		break;

	  case SASL_CB_GETREALM:
		interact->result = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_AUTHREALM];
		interact->len = strlen(interact->result);
		break;

	  case SASL_CB_AUTHNAME:
		interact->result = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_AUTHNAME];
		interact->len = strlen(interact->result);
		break;

	  case SASL_CB_USER:
		interact->result = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_AUTHUSER];
		interact->len = strlen(interact->result);
		break;

	  default:
		interact->result = "";
		interact->len = 0;
		break;
	}

	return SASL_OK;
}
#endif /* (USE_SASL && USE_LDAP) */

/*
**  DKIMF_DB_DATASPLIT -- split a database value or set of values into a
**                        request array
**
**  Parameters:
**  	buf -- data buffer
**  	buflen -- buffer length
**  	req -- request array
**  	reqnum -- length of request array
**
**  Return value:
**  	0 -- successful data split
**  	-1 -- not enough elements present to fulfill the request
*/

static int
dkimf_db_datasplit(char *buf, size_t buflen,
                   DKIMF_DBDATA req, unsigned int reqnum)
{
	int ridx;
	int ret = 0;
	size_t clen;
	size_t remain;
	char *p;

	assert(buf != NULL);

	if (req == NULL || reqnum == 0)
		return 0;

	p = buf;
	remain = buflen;

	for (ridx = 0; ridx < reqnum; ridx++)
	{
		if (remain <= 0)
			break;

		if ((req[ridx].dbdata_flags & DKIMF_DB_DATA_BINARY) != 0)
		{
			clen = MIN(remain, req[ridx].dbdata_buflen);
			memcpy(req[ridx].dbdata_buffer, p, clen);
			req[ridx].dbdata_buflen = remain;
			remain = 0;
		}
		else if (ridx == reqnum - 1)
		{
			clen = MIN(remain, req[ridx].dbdata_buflen);
			memcpy(req[ridx].dbdata_buffer, p, clen);
			req[ridx].dbdata_buflen = remain;
		}
		else
		{
			char *q;

			q = strchr(p, ':');
			if (q != NULL)
			{
				clen = q - p;
				memcpy(req[ridx].dbdata_buffer, p,
				       MIN(clen, req[ridx].dbdata_buflen));
				req[ridx].dbdata_buflen = clen;
				p += clen + 1;
				remain -= (clen + 1);
			}
			else
			{
				clen = remain;
				memcpy(req[ridx].dbdata_buffer, p,
				       MIN(clen, req[ridx].dbdata_buflen));
				req[ridx].dbdata_buflen = clen;
				remain = 0;
			}
		}
	}

	/* mark the ones that got no data */
	if (ridx < reqnum - 1)
	{
		int c;

		for (c = ridx + 1; c < reqnum; c++)
		{
			ret = -1;
			req[c].dbdata_buflen = 0;
		}
	}

        return ret;
}

#ifdef USE_LDAP
/*
**  DKIMF_DB_MKLDAPQUERY -- generate an LDAP query
**
**  Parameters:
**  	buf -- parameter (the actual query)
**  	buflen -- length of data in "buf"
**  	query -- query string (a domain name?)
**  	out -- outbut buffer
**  	outlen -- size of "out"
**
**  Return value:
**  	None.
**
**  Notes:
**  	Should report overflows.
*/

static void
dkimf_db_mkldapquery(char *buf, char *query, char *out, size_t outlen)
{
	char last = '\0';
	char *p;
	char *o;
	char *q;
	char *pend;
	char *oend;
	char *qend;

	assert(buf != NULL);
	assert(query != NULL);
	assert(out != NULL);

	p = buf;
	pend = p + strlen(p) - 1;

	q = query;
	qend = query + strlen(query) - 1;

	o = out;
	oend = out + outlen - 1;

	while (p <= pend && o <= oend)
	{
		if (last == '$')
		{
			if (*p == 'd')
			{
				for (q = query; o <= oend && q <= qend; q++)
					*o++ = *q;
			}
			else if (*p == 'D')
			{
				for (q = query; o <= oend && q <= qend; q++)
				{
					if (q == query)
					{
						o += strlcpy(o, "dc=",
						             oend - o);
						*o++ = *q;
					}
					else if (*q == '.')
					{
						o += strlcpy(o, ",dc=",
						             oend - o);
					}
					else
					{
						*o++ = *q;
					}
				}
			}
			else
			{
				*q++ = *p;
			}
		}
		else if (*p != '$')
		{
			*o++ = *p;
		}

		last = *p;
		p++;
	}
}
#endif /* USE_LDAP */

/*
**  DKIMF_DB_NEXTPUNCT -- find next punctuation
**
**  Parameters:
**  	str -- start of the search
**
**  Return value:
**  	Pointer to the next punctuation found, or NULL if none.
*/

static char *
dkimf_db_nextpunct(char *str)
{
	char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (*p == ':' ||
		    *p == '/' ||
		    *p == '@' ||
		    *p == '+' ||
		    *p == '=' ||
		    *p == '?')
			return p;
	}

	return NULL;
}

/*
**  DKIMF_DB_LIST_FREE -- destroy a linked list
**
**  Parameters:
**  	list -- list handle
**
**  Return value:
**  	None.
*/

static void
dkimf_db_list_free(struct dkimf_db_list *list)
{
	struct dkimf_db_list *next;

	assert(list != NULL);

	while (list != NULL)
	{
		free(list->db_list_key);
		if (list->db_list_value != NULL)
			free(list->db_list_value);
		next = list->db_list_next;
		free(list);
		list = next;
	}
}
		
/*
**  DKIMF_DB_RELIST_FREE -- destroy a linked regex list
**
**  Parameters:
**  	list -- list handle
**
**  Return value:
**  	None.
*/

static void
dkimf_db_relist_free(struct dkimf_db_relist *list)
{
	struct dkimf_db_relist *next;

	assert(list != NULL);

	while (list != NULL)
	{
		regfree(&list->db_relist_re);
		if (list->db_relist_data != NULL)
			free(list->db_relist_data);
		next = list->db_relist_next;
		free(list);
		list = next;
	}
}
		
/*
**  DKIMF_DB_TYPE -- return database type
**
**  Parameters:
**  	db -- DKIMF_DB handle
** 
**  Return value:
**  	A DKIMF_DB_TYPE_* constant.
*/

int
dkimf_db_type(DKIMF_DB db)
{
	assert(db != NULL);

	return db->db_type;
}

/*
**  DKIMF_DB_OPEN -- open a database
**
**  Parameters:
**  	db -- DKIMF_DB handle (returned)
**  	name -- name of DB to open
**  	flags -- operational flags
**  	lock -- lock to use during operations
**  	err -- error string from underlying library (returned; may be NULL)
**
**  Return value:
**  	3 -- other open error
**  	2 -- illegal request (e.g. writable flat file)
**  	1 -- unknown database type
**  	0 -- success
**   	-1 -- failure; check errno
**
**  Notes:
**  	The type of the database is implied by a leading "type:" string
**  	as part of "name".  The list of valid types is listed in the
**  	"dbtypes" table above.  Without such a prefix, a name that starts
**  	with "/" implies "file", otherwise "csl" is used.
**
**  	Currently defined types:
**  	csl -- "name" contains a comma-separated list
**  	file -- a flat file; may be simply a list of names if only a
**  	        memership test is needed, or it can be "key value" lines
**  	        in which case dkimf_db_get() can be used to extract the
**  	        value of a named key
**  	refile -- a flat file containing patterns (i.e. strings with the
**  	          wildcard "*"); only membership tests are allowed
**  	db -- a Sleepycat hash or b-tree database file, which can be used
**  	      for membership tests or key-value pairs
**  	dsn -- a data store name, meaning SQL or ODBC in the backend,
**  	       with interface provided by OpenDBX
**  	ldap -- an LDAP server, interace provide by OpenLDAP
**  	lua -- a Lua script; the returned value is the result
*/

int
dkimf_db_open(DKIMF_DB *db, char *name, u_int flags, pthread_mutex_t *lock,
              char **err)
{
	DKIMF_DB new;
	char *p;

	assert(db != NULL);
	assert(name != NULL);

	new = (DKIMF_DB) malloc(sizeof(struct dkimf_db));
	if (new == NULL)
	{
		if (err != NULL)
			*err = strerror(errno);
		return -1;
	}

	memset(new, '\0', sizeof(struct dkimf_db));

	new->db_flags = flags;
	new->db_type = DKIMF_DB_TYPE_UNKNOWN;

	p = strchr(name, ':');
	if (p == NULL)
	{
# ifdef USE_DB
		char *q;

		q = NULL;
		for (p = strstr(name, ".db");
		     p != NULL;
		     p = strstr(p + 1, ".db"))
			q = p;
		if (q != NULL && *(q + 3) == '\0')
			new->db_type = DKIMF_DB_TYPE_BDB;
		else
# endif /* USE_DB */
		if (name[0] == '/')
			new->db_type = DKIMF_DB_TYPE_FILE;
		else
			new->db_type = DKIMF_DB_TYPE_CSL;
		p = name;
	}
	else
	{
		int c;
		size_t clen;
		char dbtype[BUFRSZ + 1];

		memset(dbtype, '\0', sizeof dbtype);
		clen = MIN(sizeof(dbtype) - 1, p - name);
		strncpy(dbtype, name, clen);

		for (c = 0; ; c++)
		{
			if (dbtypes[c].name == NULL)
				break;

			if (strcasecmp(dbtypes[c].name, dbtype) == 0)
				new->db_type = dbtypes[c].code;
		}

		if (new->db_type == DKIMF_DB_TYPE_UNKNOWN)
		{
			free(new);
			if (err != NULL)
				*err = "Unknown database type";
			return 1;
		}

		p++;
	}

	/* force DB accesses to be mutex-protected */
	if (new->db_type == DKIMF_DB_TYPE_DSN)
		new->db_flags |= DKIMF_DB_FLAG_MAKELOCK;

	/* use provided lock, or create a new one if needed */
	if (lock != NULL)
	{
		new->db_lock = lock;
		new->db_flags &= ~DKIMF_DB_FLAG_MAKELOCK;
	}
	else if ((new->db_flags & DKIMF_DB_FLAG_MAKELOCK) != 0)
	{
		new->db_lock = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));
		if (new->db_lock == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		pthread_mutex_init(new->db_lock, NULL);
	}

	switch (new->db_type)
	{
	  case DKIMF_DB_TYPE_CSL:
	  {
		int n = 0;
		char *tmp;
		char *eq;
		char *ctx;
		struct dkimf_db_list *list = NULL;
		struct dkimf_db_list *next = NULL;
		struct dkimf_db_list *newl;

		if ((flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			free(new);
			errno = EINVAL;
			if (err != NULL)
				*err = strerror(errno);
			return 2;
		}

		tmp = strdup(p);
		if (tmp == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		for (p = strtok_r(tmp, ",", &ctx);
		     p != NULL;
		     p = strtok_r(NULL, ",", &ctx))
		{
			eq = strchr(p, '=');
			if (eq != NULL)
				*eq = '\0';

			if (eq != NULL &&
			    (new->db_flags & DKIMF_DB_FLAG_VALLIST) != 0)
			{
				char *q;
				char *ctx2;

				for (q = strtok_r(eq + 1, "|", &ctx2);
				     q != NULL;
				     q = strtok_r(NULL, "|", &ctx2))
				{
					newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
					if (newl == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(tmp);
						free(new);
						return -1;
					}

					newl->db_list_key = strdup(p);
					if (newl->db_list_key == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);
						free(tmp);
						free(new);
						return -1;
					}

					newl->db_list_value = strdup(q);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(tmp);
						free(new);
						return -1;
					}

					newl->db_list_next = NULL;

					if (list == NULL)
						list = newl;
					else
						next->db_list_next = newl;

					next = newl;
					n++;
				}
			}
			else
			{
				newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
				if (newl == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					if (list != NULL)
						dkimf_db_list_free(list);
					free(tmp);
					free(new);
					return -1;
				}

				newl->db_list_key = strdup(p);
				if (newl->db_list_key == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					free(newl);
					if (list != NULL)
						dkimf_db_list_free(list);
					free(tmp);
					free(new);
					return -1;
				}

				if (eq != NULL)
				{
					newl->db_list_value = strdup(eq + 1);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						free(tmp);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);
						return -1;
					}
				}
				else
				{
					newl->db_list_value = NULL;
				}

				newl->db_list_next = NULL;

				if (list == NULL)
					list = newl;
				else
					next->db_list_next = newl;

				next = newl;
				n++;
			}
		}

		free(tmp);

		new->db_handle = list;
		new->db_nrecs = n;

		break;
	  }

	  case DKIMF_DB_TYPE_FILE:
	  {
		_Bool gapfound;
		int n = 0;
		FILE *f;
		char *key;
		char *value;
		struct dkimf_db_list *list = NULL;
		struct dkimf_db_list *next = NULL;
		struct dkimf_db_list *newl;
		char line[BUFRSZ + 1];

		if ((flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(new);
			errno = EINVAL;
			return 2;
		}

		f = fopen(p, "r");
		if (f == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		memset(line, '\0', sizeof line);
		while (fgets(line, BUFRSZ, f) != NULL)
		{
			for (p = line; *p != '\0'; p++)
			{
				if (*p == '\n' || *p == '#')
				{
					*p = '\0';
					break;
				}
			}

			dkimf_trimspaces((u_char *) line);
			if (strlen(line) == 0)
				continue;

			newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
			if (newl == NULL)
			{
				if (err != NULL)
					*err = strerror(errno);
				if (list != NULL)
					dkimf_db_list_free(list);
				fclose(f);
				free(new);
				return -1;
			}

			key = NULL;
			value = NULL;
			gapfound = FALSE;

			for (p = line; *p != '\0'; p++)
			{
				if (!isascii(*p) || !isspace(*p))
				{
					if (key == NULL)
						key = p;
					else if (value == NULL && gapfound)
						value = p;
				}
				else if (key != NULL && value == NULL)
				{
					*p = '\0';
					gapfound = TRUE;
				}
			}

			assert(key != NULL);
			
			if (value != NULL &&
			    (new->db_flags & DKIMF_DB_FLAG_VALLIST) != 0)
			{
				char *q;
				char *ctx;

				for (q = strtok_r(value, "|", &ctx);
				     q != NULL;
				     q = strtok_r(NULL, "|", &ctx))
				{
					newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
					if (newl == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);

						return -1;
					}

					newl->db_list_key = strdup(p);
					if (newl->db_list_key == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);

						return -1;
					}

					newl->db_list_value = strdup(q);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						return -1;
					}

					newl->db_list_next = NULL;

					if (list == NULL)
						list = newl;
					else
						next->db_list_next = newl;
	
					next = newl;
					n++;
				}
			}
			else
			{
				newl->db_list_key = strdup(key);
				if (newl->db_list_key == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					free(newl);
					if (list != NULL)
						dkimf_db_list_free(list);
					fclose(f);
					free(new);
					return -1;
				}

				if (value != NULL)
				{
					newl->db_list_value = strdup(value);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						fclose(f);
						free(new);
						return -1;
					}
				}
				else
				{
					newl->db_list_value = NULL;
				}

				newl->db_list_next = NULL;

				if (list == NULL)
					list = newl;
				else
					next->db_list_next = newl;

				next = newl;
				n++;
			}
		}

		fclose(f);

		new->db_handle = list;
		new->db_nrecs = n;

		break;
	  }

	  case DKIMF_DB_TYPE_REFILE:
	  {
		int status;
		int reflags;
		FILE *f;
		char *end;
		char *data;
		struct dkimf_db_relist *head = NULL;
		struct dkimf_db_relist *tail = NULL;
		struct dkimf_db_relist *newl;
		char line[BUFRSZ + 1];
		char patbuf[BUFRSZ + 1];

		if ((flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(new);
			errno = EINVAL;
			return 2;
		}

		f = fopen(p, "r");
		if (f == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		reflags = REG_EXTENDED;
		if ((new->db_flags & DKIMF_DB_FLAG_ICASE) != 0)
			reflags |= REG_ICASE;

		memset(line, '\0', sizeof line);
		while (fgets(line, BUFRSZ, f) != NULL)
		{
			end = NULL;
			data = NULL;

			for (p = line; *p != '\0'; p++)
			{
				if (*p == '\n' || *p == '#')
				{
					*p = '\0';
					break;
				}
				else if (isascii(*p) && isspace(*p))
				{
					end = p;
				}
			}

			if (end != NULL)
			{
				*end = '\0';
				for (data = end + 1; *data != '\0'; data++)
				{
					if (!isascii(*data) || !isspace(*data))
						break;
				}
			}

			dkimf_trimspaces((u_char *) line);
			if (strlen(line) == 0)
				continue;

			newl = (struct dkimf_db_relist *) malloc(sizeof(struct dkimf_db_relist));
			if (newl == NULL)
			{
				if (err != NULL)
					*err = strerror(errno);
				if (head != NULL)
					dkimf_db_relist_free(head);
				fclose(f);
				free(new);
				free(newl);
				return -1;
			}

			memset(patbuf, '\0', sizeof patbuf);

			if (!dkimf_mkregexp(line, patbuf, sizeof patbuf))
			{
				if (err != NULL)
					*err = "Error constructing regular expression";
				if (head != NULL)
					dkimf_db_relist_free(head);
				fclose(f);
				free(new);
				free(newl);
				return -1;
			}

			status = regcomp(&newl->db_relist_re, patbuf, reflags);
			if (status != 0)
			{
				if (err != NULL)
					*err = "Error compiling regular expression";
				if (head != NULL)
					dkimf_db_relist_free(head);
				fclose(f);
				free(new);
				free(newl);
				return -1;
			}

			if (data != NULL)
			{
				newl->db_relist_data = strdup(data);
				if (newl->db_relist_data == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					if (head != NULL)
						dkimf_db_relist_free(head);
					fclose(f);
					free(new);
					free(newl);
					return -1;
				}
			}
			else
			{
				newl->db_relist_data = NULL;
			}

			newl->db_relist_next = NULL;

			if (head == NULL)
				head = newl;
			else
				tail->db_relist_next = newl;

			tail = newl;
		}

		fclose(f);

		new->db_handle = head;

		break;
	  }

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
	  {
# if DB_VERSION_CHECK(2,0,0)
		int dbflags = 0;
# endif /* DB_VERSION_CHECK(2,0,0) */
		int status = 0;
		DBTYPE bdbtype;
		DB *newdb;

# if DB_VERSION_CHECK(2,0,0)
		if (flags & DKIMF_DB_FLAG_READONLY)
		{
			dbflags |= DB_RDONLY;
			bdbtype = DB_UNKNOWN;
		}
		else
		{
			dbflags |= DB_CREATE;
			bdbtype = DB_HASH;
		}
# else /* DB_VERSION_CHECK(2,0,0) */
		bdbtype = DB_HASH;
# endif /* DB_VERSION_CHECK(2,0,0) */

#ifdef _FFR_LDAP_CACHING
		if (*p == '\0' && (flags & DKIMF_DB_FLAG_READONLY) == 0)
			p = NULL;
#endif /* _FFR_LDAP_CACHING */

# if DB_VERSION_CHECK(3,0,0)
		status = db_create(&newdb, NULL, 0);
		if (status == 0)
		{
#  if DB_VERSION_CHECK(4,1,25)
 			status = newdb->open(newdb, NULL, p, NULL,
			                       bdbtype, dbflags, 0);
#  else /* DB_VERSION_CHECK(4,1,25) */
			status = newdb->open(newdb, p, NULL, bdbtype,
			                     dbflags, 0);
#  endif /* DB_VERSION_CHECK(4,1,25) */
		}
# elif DB_VERSION_CHECK(2,0,0)
		status = db_open(p, bdbtype, dbflags, DKIMF_DB_MODE,
		                 NULL, NULL, &newdb);
# else /* DB_VERSION_CHECK(2,0,0) */
		newdb = dbopen(p,
		               (flags & DKIMF_DB_FLAG_READONLY ? O_RDONLY
		                                                : (O_CREAT|O_RDWR)),
		               DKIMF_DB_MODE, bdbtype, NULL);
		if (newdb == NULL)
			status = errno;
# endif /* DB_VERSION_CHECK */

		if (status != 0)
		{
			if (err != NULL)
				*err = DB_STRERROR(status);
			free(new);
			return 3;
		}

		new->db_handle = newdb;

		break;
	  }
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
	  {
		_Bool found;
		int dberr;
		struct dkimf_db_dsn *dsn;
		char *q;
		char *r;
		char *eq;
		char *tmp;
		odbx_t *odbx;

		dsn = (struct dkimf_db_dsn *) malloc(sizeof(struct dkimf_db_dsn));
		if (dsn == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		memset(dsn, '\0', sizeof *dsn);

		/*
		**  General format of a DSN:
		**  <backend>://[user[:pwd]@][port+]host/dbase[/key=val[?...]]
		**  
		**  "table", "keycol" and "datacol" will be set in one of the
		**  key-value pairs.
		*/

		tmp = strdup(p);
		if (tmp == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(dsn);
			free(new);
			return -1;
		}

		q = strchr(tmp, ':');
		if (q == NULL)
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(dsn);
			free(tmp);
			free(new);
			return -1;
		}

		*q = '\0';
		strlcpy(dsn->dsn_backend, tmp, sizeof dsn->dsn_backend);

		q++;
		if (*q != '/' || *(q + 1) != '/')
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(dsn);
			free(tmp);
			return -1;
		}

		q += 2;
		found = FALSE;
		for (p = dkimf_db_nextpunct(q);
		     !found && p != NULL;
		     p = dkimf_db_nextpunct(q))
		{
			switch (*p)
			{
			  case ':':
				*p = '\0';

				if (dsn->dsn_user[0] != '\0')
				{
					if (err != NULL)
						*err = strerror(EINVAL);
					free(dsn);
					free(tmp);
					free(new);
					return -1;
				}

				strlcpy(dsn->dsn_user, q,
				        sizeof dsn->dsn_user);
				q = p + 1;
				break;

			  case '@':
				*p = '\0';

				if (dsn->dsn_user[0] == '\0')
				{
					strlcpy(dsn->dsn_user, q,
					        sizeof dsn->dsn_user);
				}
				else
				{
					strlcpy(dsn->dsn_password, q,
					        sizeof dsn->dsn_password);
				}

				q = p + 1;
				break;

			  case '+':
				*p = '\0';

				strlcpy(dsn->dsn_port, q,
				        sizeof dsn->dsn_port);

				q = p + 1;
				break;

			  case '/':
				*p = '\0';
				if (dsn->dsn_host[0] == '\0')
				{
					strlcpy(dsn->dsn_host, q,
					        sizeof dsn->dsn_host);
				}
				else
				{
					found = TRUE;
					strlcpy(dsn->dsn_dbase, q,
					        sizeof dsn->dsn_dbase);
				}
				q = p + 1;
				break;

			  default:
				if (err != NULL)
					*err = strerror(EINVAL);
				free(dsn);
				free(tmp);
				free(new);
				return -1;
			}
		}

		if (dsn->dsn_host[0] == '\0')
		{
			if (err != NULL)
				*err = "SQL host not defined";
			free(dsn);
			free(tmp);
			free(new);
			return -1;
		}

		for (p = strtok_r(q, "?", &r);
		     p != NULL;
		     p = strtok_r(NULL, "?", &r))
		{
			eq = strchr(p, '=');
			if (eq == NULL)
				continue;

			*eq = '\0';
			if (strcasecmp(p, "table") == 0)
			{
				strlcpy(dsn->dsn_table, eq + 1,
				        sizeof dsn->dsn_table);
			}
			else if (strcasecmp(p, "keycol") == 0)
			{
				strlcpy(dsn->dsn_keycol, eq + 1,
				        sizeof dsn->dsn_keycol);
			}
			else if (strcasecmp(p, "datacol") == 0)
			{
				strlcpy(dsn->dsn_datacol, eq + 1,
				        sizeof dsn->dsn_datacol);
			}
		}

		/* error out if one of the required parameters was absent */
		if (dsn->dsn_table[0] == '\0' ||
		    dsn->dsn_keycol[0] == '\0' ||
		    dsn->dsn_datacol[0] == '\0')
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(dsn);
			free(tmp);
			return -1;
		}

# define STRORNULL(x)	((x)[0] == '\0' ? NULL : (x))

		/* create odbx handle */
		dberr = odbx_init(&odbx,
		                  STRORNULL(dsn->dsn_backend),
		                  STRORNULL(dsn->dsn_host),
		                  STRORNULL(dsn->dsn_port));
		if (dberr < 0)
		{
			if (err != NULL)
				*err = (char *) odbx_error(NULL, dberr);
			free(dsn);
			free(tmp);
			return -1;
		}

		/* create bindings */
		dberr = odbx_bind(odbx, STRORNULL(dsn->dsn_dbase),
		                        STRORNULL(dsn->dsn_user),
		                        STRORNULL(dsn->dsn_password),
		                        ODBX_BIND_SIMPLE);
		if (dberr < 0)
		{
			if (err != NULL)
				*err = (char *) odbx_error(NULL, dberr);
			(void) odbx_finish(odbx);
			free(dsn);
			free(tmp);
			free(new);
			return -1;
		}

		/* store handle */
		new->db_handle = (void *) odbx;
		new->db_data = (void *) dsn;

		/* clean up */
		free(tmp);
		break;
	  }
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		_Bool found;
		_Bool usetls = FALSE;
		int c;
		int lderr;
		int v = LDAP_VERSION3;
		size_t rem;
		size_t plen;
		struct dkimf_db_ldap *ldap;
		LDAP *ld;
		char *q;
		char *r;
		char *u;
		LDAPURLDesc *descr;
#ifdef _FFR_LDAP_CACHING
# ifdef USE_DB
		DB *newdb;
# endif /* USE_DB */
#endif /* _FFR_LDAP_CACHING */
		char *uris[DKIMF_LDAP_MAXURIS];

		memset(uris, '\0', sizeof uris);

		p = strdup(name);
		if (p == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		/* make sure they're all valid LDAP URIs */
		for (q = strtok_r(p, " \t", &r), c = 0;
		     q != NULL;
		     q = strtok_r(NULL, " \t", &r), c++)
		{
			if (ldap_is_ldap_url(q) == 0)
			{
				if (err != NULL)
					*err = strerror(EINVAL);
				free(p);
				free(new);
				return -1;
			}

			/* store the first N of them */
			if (c < DKIMF_LDAP_MAXURIS)
				uris[c] = q;
		}

		ldap = (struct dkimf_db_ldap *) malloc(sizeof(struct dkimf_db_ldap));
		if (ldap == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(p);
			free(new);
			return -1;
		}

		memset(ldap, '\0', sizeof *ldap);
		ldap->ldap_timeout = DKIMF_LDAP_TIMEOUT;

		/*
		**  General format of an LDAP specification:
		**  scheme://host[:port][/dn[?attrs[?scope[?filter[?exts]]]]]
		**  (see RFC4516)
		**  
		**  "bindpass", "authmech" and "usetls" will be set in
		**  other config values.
		**  
		**  Take the descriptive values (e.g. attributes) from the
		**  first one.
		*/

		lderr = ldap_url_parse(uris[0], &ldap->ldap_descr);
		if (lderr != 0)
		{
			if (err != NULL)
				*err = ldap_err2string(lderr);
			free(ldap);
			free(p);
			free(new);
			return -1;
		}

		/* construct the URI list for this handle */
		rem = sizeof ldap->ldap_urilist;
		q = ldap->ldap_urilist;
		for (c = 0; c < DKIMF_LDAP_MAXURIS; c++)
		{
			if (uris[c] == NULL)
				break;

			(void) ldap_url_parse(uris[c], &descr);

			if (c != 0)
			{
				*q = ' ';
				q++;
				rem--;
			}

			plen = snprintf(q, rem, "%s://%s:%d",
			                descr->lud_scheme,
			                descr->lud_host,
			                descr->lud_port);


			if (plen >= rem)
			{
				if (err != NULL)
					*err = "LDAP URI too large";
				free(ldap);
				free(p);
				free(new);
				return -1;
			}

			rem -= plen;

			ldap_free_urldesc(descr);
		}

		/* create LDAP handle */
		lderr = ldap_initialize(&ld, ldap->ldap_urilist);
		if (lderr != LDAP_SUCCESS)
		{
			if (err != NULL)
				*err = ldap_err2string(lderr);
			free(ldap);
			free(p);
			free(new);
			return -1;
		}

		/* set LDAP version */
		lderr = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &v);
		if (lderr != LDAP_OPT_SUCCESS)
		{
			if (err != NULL)
				*err = ldap_err2string(lderr);
			ldap_unbind_ext(ld, NULL, NULL);
			free(ldap);
			free(p);
			free(new);
			return -1;
		}

		/* attempt TLS if requested, except for ldaps and ldapi */
		q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_USETLS];
		if (q != NULL && (*q == 'y' || *q == 'Y') &&
		    strcasecmp(ldap->ldap_descr->lud_scheme, "ldapi") != 0 &&
		    strcasecmp(ldap->ldap_descr->lud_scheme, "ldaps") != 0)
		{
			lderr = ldap_start_tls_s(ld, NULL, NULL);
			if (lderr != LDAP_SUCCESS)
			{
				if (err != NULL)
					*err = ldap_err2string(lderr);
				ldap_unbind_ext(ld, NULL, NULL);
				free(ldap);
				free(p);
				free(new);
				return -1;
			}
		}

		/* attempt binding */
		q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_AUTHMECH];
		u = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_BINDUSER];
		if (q == NULL || strcasecmp(q, "none") == 0 ||
		    strcasecmp(q, "simple") == 0)
		{
			struct berval passwd;

			r = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_BINDPW];
			if (r != NULL)
			{
				passwd.bv_val = r;
				passwd.bv_len = strlen(r);
			}
			else
			{
				passwd.bv_val = NULL;
				passwd.bv_len = 0;
			}

			lderr = ldap_sasl_bind_s(ld, u, q, &passwd,
			                         NULL, NULL, NULL);
			if (lderr != LDAP_SUCCESS)
			{
				if (err != NULL)
					*err = ldap_err2string(lderr);
				ldap_unbind_ext(ld, NULL, NULL);
				free(ldap);
				free(p);
				free(new);
				return -1;
			}
		}
		else
		{
# ifdef USE_SASL
			lderr = ldap_sasl_interactive_bind_s(ld,
			                                     u,	/* bind user */
			                                     q,	/* SASL mech */
			                                     NULL, /* controls */
			                                     NULL, /* controls */
			                                     LDAP_SASL_QUIET, /* flags */
			                                     dkimf_db_saslinteract, /* callback */
			                                     NULL);
			if (lderr != LDAP_SUCCESS)
			{
				if (err != NULL)
					*err = ldap_err2string(lderr);
				ldap_unbind_ext(ld, NULL, NULL);
				free(ldap);
				free(p);
				free(new);
				return -1;
			}
# else /* USE_SASL */
			/* unknown auth mechanism */
			if (err != NULL)
				*err = "Unknown auth mechanism";
			ldap_unbind_ext(ld, NULL, NULL);
			free(ldap);
			free(p);
			free(new);
			return -1;
# endif /* USE_SASL */
		}

		pthread_mutex_init(&ldap->ldap_lock, NULL);

# ifdef _FFR_LDAP_CACHING
#  ifdef USE_DB
		/* establish LDAP cache DB */
		lderr = 0;

#   if DB_VERSION_CHECK(3,0,0)
		lderr = db_create(&newdb, NULL, 0);
		if (lderr == 0)
		{
#    if DB_VERSION_CHECK(4,1,25)
 			lderr = newdb->open(newdb, NULL, NULL, NULL,
			                    DB_HASH, 0, 0);
#    else /* DB_VERSION_CHECK(4,1,25) */
			lderr = newdb->open(newdb, NULL, NULL, DB_HASH, 0, 0);
#    endif /* DB_VERSION_CHECK(4,1,25) */
		}
#   elif DB_VERSION_CHECK(2,0,0)
		lderr = db_open(NULL, DB_HASH, 0, DKIMF_DB_MODE,
		                NULL, NULL, &newdb);
#   else /* DB_VERSION_CHECK(2,0,0) */
		newdb = dbopen(NULL, (O_CREAT|O_RDWR),
		               DKIMF_DB_MODE, DB_HASH, NULL);
		if (newdb == NULL)
			lderr = errno;
#   endif /* DB_VERSION_CHECK */

		if (lderr == 0)
		{
			DKIMF_DB cachedb;

			cachedb = malloc(sizeof *cachedb);
			if (cachedb != NULL)
			{
				memset(cachedb, '\0', sizeof *cachedb);

				cachedb->db_type = DKIMF_DB_TYPE_BDB;
				cachedb->db_handle = newdb;

				ldap->ldap_cache = cachedb;
			}
			else
			{
				DKIMF_DBCLOSE(newdb);
			}
		}
#  endif /* USE_DB */
# endif /* _FFR_LDAP_CACHING */

		/* store handle */
		new->db_handle = (void *) ld;
		new->db_data = (void *) ldap;

		/* clean up */
		free(p);
		break;
	  }
#endif /* USE_LDAP */

#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		int fd;
		ssize_t rlen;
		struct stat s;
		struct dkimf_db_lua *lua;

		fd = open(p, O_RDONLY);
		if (fd < 0)
		{
			if (err != NULL)
				*err = strerror(errno);
			return -1;
		}

		if (fstat(fd, &s) == -1)
		{
			if (err != NULL)
				*err = strerror(errno);
			close(fd);
			return -1;
		}

		lua = (struct dkimf_db_lua *) malloc(sizeof *lua);
		if (lua == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			return -1;
		}
		memset(lua, '\0', sizeof *lua);
		new->db_data = (void *) lua;

		lua->lua_script = (void *) malloc(s.st_size + 1);
		if (lua->lua_script == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new->db_data);
			close(fd);
			return -1;
		}
		memset(lua->lua_script, '\0', s.st_size + 1);

		rlen = read(fd, lua->lua_script, s.st_size);
		if (rlen < s.st_size)
		{
			if (err != NULL)
			{
				if (rlen == -1)
					*err = strerror(errno);
				else
					*err = "Read truncated";
			}
			free(lua->lua_script);
			free(new->db_data);
			close(fd);
			return -1;
		}
	  }
#endif /* USE_LUA */
	}

	*db = new;
	return 0;
}

/*
**  DKIMF_DB_DELETE -- delete a key/data pair from an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- pointer to record to be deleted
**  	buflen -- size of record at "buf"; if 0, use strlen()
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
*/

int
dkimf_db_delete(DKIMF_DB db, void *buf, size_t buflen)
{
	int ret = EINVAL;
#ifdef USE_DB
	DBT q;
	int fd;
	int status;
	DB *bdb;
#endif /* USE_DB */

	assert(db != NULL);
	assert(buf != NULL);

	if (db->db_type == DKIMF_DB_TYPE_FILE ||
	    db->db_type == DKIMF_DB_TYPE_CSL || 
	    db->db_type == DKIMF_DB_TYPE_DSN || 
	    db->db_type == DKIMF_DB_TYPE_LDAP || 
	    db->db_type == DKIMF_DB_TYPE_LUA || 
	    db->db_type == DKIMF_DB_TYPE_REFILE)
		return EINVAL;

#ifdef USE_DB
	bdb = (DB *) db->db_handle;

	memset(&q, 0, sizeof q);
	q.data = (char *) buf;
	q.size = (buflen == 0 ? strlen(q.data) : buflen);

	ret = 0;

	/* establish write-lock */
	fd = -1;
# if DB_VERSION_CHECK(2,0,0)
	status = bdb->fd(bdb, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
	status = 0;
	fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */

	if (db->db_lock != NULL)
		(void) pthread_mutex_lock(db->db_lock);

	if (status == 0 && fd != -1)
	{
# ifdef LOCK_EX
		status = flock(fd, LOCK_EX);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# else /* LOCK_EX */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_WRLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# endif /* LOCK_EX */
	}

# if DB_VERSION_CHECK(2,0,0)
	status = bdb->del(bdb, NULL, &q, 0);
	if (status == 0)
		ret = 0;
	else
		ret = status;
# else /* DB_VERSION_CHECK(2,0,0) */
	status = bdb->del(bdb, &q, 0);
	if (status == 1)
		ret = -1;
	else if (status == 0)
		ret = 0;
	else
		ret = errno;
# endif /* DB_VERSION_CHECK(2,0,0) */

	/* surrender write-lock */
	if (fd != -1)
	{
# ifdef LOCK_UN
		status = flock(fd, LOCK_UN);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# else /* LOCK_UN */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_UNLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# endif /* LOCK_UN */
	}

	if (db->db_lock != NULL)
		(void) pthread_mutex_unlock(db->db_lock);
#endif /* USE_DB */

	return ret;
}

/*
**  DKIMF_DB_PUT -- store a key/data pair in an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- pointer to key record
**  	buflen -- size of key (use strlen() if 0)
**  	outbuf -- data buffer
**  	outbuflen -- number of bytes at outbuf to use as data
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
*/

int
dkimf_db_put(DKIMF_DB db, void *buf, size_t buflen,
             void *outbuf, size_t outbuflen)
{
	int ret = EINVAL;
#ifdef USE_DB
	DBT d;
	DBT q;
	int fd;
	int status;
	DB *bdb;
#endif /* USE_DB */

	assert(db != NULL);
	assert(buf != NULL);
	assert(outbuf != NULL);

	if (db->db_type == DKIMF_DB_TYPE_FILE ||
	    db->db_type == DKIMF_DB_TYPE_CSL || 
	    db->db_type == DKIMF_DB_TYPE_DSN || 
	    db->db_type == DKIMF_DB_TYPE_LDAP || 
	    db->db_type == DKIMF_DB_TYPE_LUA || 
	    db->db_type == DKIMF_DB_TYPE_REFILE)
		return EINVAL;

#ifdef USE_DB
	bdb = (DB *) db->db_handle;

	memset(&d, 0, sizeof d);
	memset(&q, 0, sizeof q);

	d.data = outbuf;
	d.size = outbuflen;
# if DB_VERSION_CHECK(2,0,0)
	d.ulen = d.size;
	d.flags = DB_DBT_USERMEM;
# endif /* DB_VERSION_CHECK(2,0,0) */

	q.data = (char *) buf;
	q.size = (buflen == 0 ? strlen(q.data) : buflen);
# if DB_VERSION_CHECK(2,0,0)
	q.ulen = q.size;
	q.flags = DB_DBT_USERMEM;
# endif /* DB_VERSION_CHECK(2,0,0) */

	ret = 0;

	/* establish write-lock */
	fd = -1;
# if DB_VERSION_CHECK(2,0,0)
	status = bdb->fd(bdb, &fd);
	if (status != 0)
	{
		db->db_status = status;
		return status;
	}
# else /* DB_VERSION_CHECK(2,0,0) */
	status = 0;
	fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */

	if (db->db_lock != NULL)
		(void) pthread_mutex_lock(db->db_lock);

	if (status == 0 && fd != -1)
	{
# ifdef LOCK_EX
		status = flock(fd, LOCK_EX);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# else /* LOCK_EX */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_WRLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# endif /* LOCK_EX */
	}

# if DB_VERSION_CHECK(2,0,0)
	status = bdb->put(bdb, NULL, &q, &d, 0);
	if (status == 0)
	{
		ret = 0;
	}
	else
	{
		db->db_status = status;
		ret = status;
	}
# else /* DB_VERSION_CHECK(2,0,0) */
	status = bdb->put(bdb, &q, &d, 0);
	if (status == 1)
	{
		ret = -1;
	}
	else if (status == 0)
	{
		ret = 0;
	}
	else
	{
		db->db_status = status;
		ret = errno;
	}
# endif /* DB_VERSION_CHECK(2,0,0) */

	/* surrender write-lock */
	if (fd != -1)
	{
# ifdef LOCK_UN
		status = flock(fd, LOCK_UN);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# else /* LOCK_UN */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_UNLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);
		if (status != 0)
		{
			db->db_status = status;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
# endif /* LOCK_UN */
	}

	if (db->db_lock != NULL)
		(void) pthread_mutex_unlock(db->db_lock);
#endif /* USE_DB */

	return ret;
}

/*
**  DKIMF_DB_GET -- retrieve data from an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- pointer to the key
**  	buflen -- length of key (use strlen() if 0)
**  	req -- list of data requests
**  	reqnum -- number of data requests
**  	exists -- pointer to a "_Bool" updated to be TRUE if the record
**  	          was found, FALSE otherwise (may be NULL)
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
**
**  Notes:
**  	"req" references a caller-provided array of DKIMF_DBDATA
**  	structures that describe the name of the attribute wanted,
**  	the location to which to write the data, and how big that buffer is.
**  	On completion, any found attributes will have their lengths
**  	set to the number of bytes retrieved and the data will be copied
**  	up to the limit (if more data was retrieved than the space available,
**  	the available space will be filled but the returned length will be
**  	longer); any not-found attributes will leave the buffers unchanged
**  	and the lengths will be set to (unsigned int) -1.
**
**  	For LDAP queries, the attribute name is used as the LDAP attribute
**  	name in the request.
**
**  	For SQL queries, the attribute name is not used; columns are specified
**  	in the DSN (see dkimf_db_open() above), and are copied into the
**  	request in order.
**
**  	For backward compatibility, text values in the other databases
**  	that are colon-delimited will be parsed as such, and the requested
**  	values will be filled in in order (so for "aaa:bbb", "aaa" will be
**  	copied into the first attribute, "bbb" will be copied to the second,
**  	and all others will receive no data.
*/

int
dkimf_db_get(DKIMF_DB db, void *buf, size_t buflen,
             DKIMF_DBDATA req, unsigned int reqnum, _Bool *exists)
{
	_Bool matched;

	assert(db != NULL);
	assert(buf != NULL);
	assert(req != NULL || reqnum == 0);

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
	  {
		struct dkimf_db_list *list;

		for (list = (struct dkimf_db_list *) db->db_handle;
		     list != NULL;
		     list = list->db_list_next)
		{
			matched = FALSE;

			if ((db->db_flags & DKIMF_DB_FLAG_ICASE) == 0)
			{
				if (strcmp(buf, list->db_list_key) == 0)
					matched = TRUE;
			}
			else
			{
				if (strcasecmp(buf, list->db_list_key) == 0)
					matched = TRUE;
			}

			if (!matched)
				continue;

			if ((db->db_flags & DKIMF_DB_FLAG_MATCHBOTH) == 0 ||
			    reqnum == 0 || list->db_list_value == NULL)
				break;

			matched = FALSE;
			assert(list->db_list_value != NULL);

			if ((db->db_flags & DKIMF_DB_FLAG_ICASE) == 0)
			{
				if (strncmp(req[0].dbdata_buffer,
				            list->db_list_value,
				            req[0].dbdata_buflen) == 0)
					matched = TRUE;
			}
			else
			{
				if (strncasecmp(req[0].dbdata_buffer,
				                list->db_list_value,
				                req[0].dbdata_buflen) == 0)
					matched = TRUE;
			}

			if (matched)
				break;
		}

		if (list == NULL)
		{
			if (exists != NULL)
				*exists = FALSE;
		}
		else
		{
			if (exists != NULL)
				*exists = TRUE;
			if (list->db_list_value != NULL && reqnum != 0)
			{
				if (dkimf_db_datasplit(list->db_list_value,
				                       strlen(list->db_list_value),
				                       req, reqnum) != 0)
					return -1;
			}
		}

		return 0;
	  }

	  case DKIMF_DB_TYPE_REFILE:
	  {
		struct dkimf_db_relist *list;

		list = (struct dkimf_db_relist *) db->db_handle;

		while (list != NULL)
		{
			if (regexec(&list->db_relist_re, buf, 0, NULL, 0) == 0)
			{
				if (exists != NULL)
					*exists = TRUE;

				if (reqnum != 0 &&
				    list->db_relist_data != NULL)
				{
					if (dkimf_db_datasplit(list->db_relist_data,
					                       strlen(list->db_relist_data),
					                       req,
					                       reqnum) != 0)
						return -1;
				}

				return 0;
			}

			list = list->db_relist_next;
		}

		if (exists != NULL)
			*exists = FALSE;

		return 0;
	  }

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
	  {
		int ret;
		int status;
		int fd;
		DB *bdb;
		DBT d;
		DBT q;
		char databuf[BUFRSZ + 1];

		bdb = (DB *) db->db_handle;

		memset(&d, 0, sizeof d);
		memset(&q, 0, sizeof q);
		q.data = (char *) buf;
		q.size = (buflen == 0 ? strlen(q.data) : buflen);

		ret = 0;

# if DB_VERSION_CHECK(2,0,0)
		d.flags = DB_DBT_USERMEM;
		d.ulen = BUFRSZ;
# endif /* DB_VERSION_CHECK(2,0,0) */
		d.data = databuf;
		d.size = BUFRSZ;

		memset(databuf, '\0', sizeof databuf);

		/* establish read-lock */
		fd = -1;
# if DB_VERSION_CHECK(2,0,0)
		status = bdb->fd(bdb, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
		status = 0;
		fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */

		/* single-thread readers since we can only lock the DB once */
		if (db->db_lock != NULL)
			(void) pthread_mutex_lock(db->db_lock);

		if (status == 0 && fd != -1)
		{
# ifdef LOCK_SH
			status = flock(fd, LOCK_SH);
			if (status != 0)
			{
				db->db_status = status;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return -1;
			}
# else /* LOCK_SH */
			struct flock l;

			l.l_start = 0;
			l.l_len = 0;
			l.l_type = F_RDLCK;
			l.l_whence = SEEK_SET;

			status = fcntl(fd, F_SETLKW, &l);
			if (status != 0)
			{
				db->db_status = status;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return -1;
			}
# endif /* LOCK_SH */
		}

# if DB_VERSION_CHECK(2,0,0)
		status = bdb->get(bdb, NULL, &q, &d, 0);
		if (status == 0)
		{
			if (exists != NULL)
				*exists = TRUE;

			ret = 0;
			if (reqnum != 0)
			{
				ret = dkimf_db_datasplit(databuf, d.size,
				                         req, reqnum);
			}

		}
		else if (status == DB_NOTFOUND)
		{
			if (exists != NULL)
				*exists = FALSE;
			ret = 0;
		}
		else
		{
			db->db_status = status;
			ret = status;
		}
# else /* DB_VERSION_CHECK(2,0,0) */
		status = bdb->get(bdb, &q, &d, 0);
		if (status == 1)
		{
			if (exists != NULL)
				*exists = FALSE;
			ret = 0;
		}
		else if (status == 0)
		{
			size_t clen;

			if (exists != NULL)
				*exists = TRUE;

			clen = MIN(sizeof databuf - 1, d.size);
			memset(databuf, '\0', sizeof databuf);
			memcpy(databuf, d.data, clen);

			ret = 0;
			if (reqnum != 0)
			{
				ret = dkimf_db_datasplit(databuf, clen,
				                         req, reqnum);
			}
		}
		else
		{
			db->db_status = errno;
			ret = errno;
		}
# endif /* DB_VERSION_CHECK(2,0,0) */

		/* surrender read-lock */
		if (fd != -1)
		{
# ifdef LOCK_SH
			status = flock(fd, LOCK_UN);
			if (status != 0)
			{
				db->db_status = status;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return -1;
			}
# else /* LOCK_SH */
			struct flock l;

			l.l_start = 0;
			l.l_len = 0;
			l.l_type = F_UNLCK;
			l.l_whence = SEEK_SET;

			status = fcntl(fd, F_SETLKW, &l);
			if (status != 0)
			{
				db->db_status = status;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return -1;
			}
# endif /* LOCK_SH */
		}

		if (db->db_lock != NULL)
			(void) pthread_mutex_unlock(db->db_lock);

		return ret;
	  }
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
	  {
		int err;
		int fields;
		int rescnt = 0;
		int rowcnt = 0;
		u_long elen;
		odbx_result_t *result;
		struct dkimf_db_dsn *dsn;
		char query[BUFRSZ];
		char escaped[BUFRSZ];

		dsn = (struct dkimf_db_dsn *) db->db_data;

		if (db->db_lock != NULL)
			(void) pthread_mutex_lock(db->db_lock);

		/* see if we need to reopen */
		if ((db->db_iflags & DKIMF_DB_IFLAG_RECONNECT) != 0)
		{
			err = odbx_init((odbx_t **) &db->db_handle,
			                STRORNULL(dsn->dsn_backend),
			                STRORNULL(dsn->dsn_host),
			                STRORNULL(dsn->dsn_port));
			if (err < 0)
			{
				db->db_status = err;
				return -1;
			}

			err = odbx_bind((odbx_t *) db->db_handle,
			                STRORNULL(dsn->dsn_dbase),
		                        STRORNULL(dsn->dsn_user),
		                        STRORNULL(dsn->dsn_password),
		                        ODBX_BIND_SIMPLE);
			if (err < 0)
			{
				(void) odbx_finish((odbx_t *) db->db_handle);
				db->db_status = err;
				return -1;
			}

			db->db_iflags &= ~DKIMF_DB_IFLAG_RECONNECT;
		}

		memset(&elen, '\0', sizeof elen);
		elen = sizeof escaped - 1;
		err = odbx_escape((odbx_t *) db->db_handle, buf,
		                  (buflen == 0 ? strlen(buf) : buflen),
		                  escaped, &elen);
		if (err < 0)
		{
			db->db_status = err;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return err;
		}

		snprintf(query, sizeof query,
		         "SELECT %s FROM %s WHERE %s = '%s'",
		         dsn->dsn_datacol,
		         dsn->dsn_table,
		         dsn->dsn_keycol, escaped);

		err = odbx_query((odbx_t *) db->db_handle, query, 0);
		if (err < 0)
		{
			db->db_status = err;
			if (odbx_error_type((odbx_t *) db->db_handle, err) < 0)
			{
				(void) odbx_unbind((odbx_t *) db->db_handle);
				(void) odbx_finish((odbx_t *) db->db_handle);
				db->db_iflags |= DKIMF_DB_IFLAG_RECONNECT;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return dkimf_db_get(db, buf, buflen, req,
				                    reqnum, exists);
			}
			else
			{
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return err;
			}
		}

		for (rescnt = 0; ; rescnt++)
		{
			err = odbx_result((odbx_t *) db->db_handle,
			                  &result, NULL, 0);
			if (err < 0)
			{
				db->db_status = err;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return err;
			}
			else if (err == ODBX_RES_DONE)
			{
				if (exists != NULL && rescnt == 0)
					*exists = FALSE;
				err = odbx_result_finish(result);
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return 0;
			}

			for (rowcnt = 0; ; rowcnt++)
			{
				err = odbx_row_fetch(result);
				if (err < 0)
				{
					db->db_status = err;
					err = odbx_result_finish(result);
					if (db->db_lock != NULL)
						(void) pthread_mutex_unlock(db->db_lock);
					return db->db_status;
				}
				else if (err == ODBX_RES_DONE)
				{
					if (exists != NULL && rescnt == 0 &&
					    rowcnt == 0)
						*exists = FALSE;
					break;
				}

				/* only copy out the first hit */
				if (rescnt == 0 && rowcnt == 0)
				{
					fields = odbx_column_count(result);
					if (fields == 0)
						continue;

					if (exists != NULL)
						*exists = TRUE;

					if (reqnum != 0)
					{
						int c;

						for (c = 0; c < reqnum; c++)
						{
							if (c >= fields)
							{
								req[c].dbdata_buflen = 0;
							}
							else
							{
								char *val;

								val = (char *) odbx_field_value(result,
								                                c);

								if (val == NULL)
								{
									req[c].dbdata_buflen = 0;
								}
								else
								{
									req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
									                               val,
									                               req[c].dbdata_buflen);
								}
							}
						}
					}
				}
			}

			err = odbx_result_finish(result);
		}

		if (db->db_lock != NULL)
			(void) pthread_mutex_unlock(db->db_lock);

		return 0;
	  }
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		int c;
		int status;
		LDAP *ld;
		LDAPMessage *result;
		LDAPMessage *e;
		struct dkimf_db_ldap *ldap;
#ifdef _FFR_LDAP_CACHING
# ifdef USE_DB
		struct dkimf_db_ldap_cache *ldc = NULL;
# endif /* USE_DB */
#endif /* _FFR_LDAP_CACHING */
		struct berval **vals;
		char query[BUFRSZ];
		char filter[BUFRSZ];
		struct timeval timeout;

		ld = (LDAP *) db->db_handle;
		ldap = (struct dkimf_db_ldap *) db->db_data;

		pthread_mutex_lock(&ldap->ldap_lock);

#ifdef _FFR_LDAP_CACHING
# ifdef USE_DB
		if (ldap->ldap_cache != NULL)
		{
			_Bool cex = FALSE;
			struct dkimf_db_data dbd;

			dbd.dbdata_buffer = (char *) &ldc;
			dbd.dbdata_buflen = sizeof ldc;
			dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;

			status = dkimf_db_get(ldap->ldap_cache, buf, buflen,
			                      &dbd, 1, &cex);

			if (cex)
			{
				struct timeval now;
				struct dkimf_db_ldap_cache_result *r;

				(void) gettimeofday(&now, NULL);

				if (ldc->ldc_state == DKIMF_DB_CACHE_DATA &&
				    ldc->ldc_absent)
				{
					if (exists != NULL)
						*exists = FALSE;

					pthread_mutex_unlock(&ldap->ldap_lock);
					return 0;
				}
				else if (ldc->ldc_state == DKIMF_DB_CACHE_DATA &&
				         ldc->ldc_expire <= now.tv_sec)
				{
					ldc->ldc_state = DKIMF_DB_CACHE_PENDING;
				}
				else if (ldc->ldc_state == DKIMF_DB_CACHE_DATA &&
				         ldc->ldc_error != 0)
				{
					pthread_mutex_unlock(&ldap->ldap_lock);
					return ldc->ldc_error;
				}
				else if (ldc->ldc_state == DKIMF_DB_CACHE_DATA &&
				         ldc->ldc_expire > now.tv_sec)
				{
					if (exists != NULL)
						*exists = TRUE;

					for (c = 0;
					     c < reqnum && c < ldc->ldc_nresults;
					     c++)
					{
						req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
						                               ldc->ldc_results[c],
						                               req[c].dbdata_buflen);
					}

					while (c < reqnum)
						req[c++].dbdata_buflen = 0;

					pthread_mutex_unlock(&ldap->ldap_lock);

					return 0;
				}
				else if (ldc->ldc_state == DKIMF_DB_CACHE_PENDING)
				{
					struct timespec timeout;

					timeout.tv_sec = now.tv_sec + ldap->ldap_timeout;
					timeout.tv_nsec = now.tv_usec * 1000;

					ldc->ldc_waiters++;

					while (ldc->ldc_state == DKIMF_DB_CACHE_PENDING)
					{
						status = pthread_cond_timedwait(&ldc->ldc_cond,
						                                &ldap->ldap_lock,
						                                &timeout);
						if (status != 0)
						{
							pthread_mutex_unlock(&ldap->ldap_lock);
							return status;
						}
					}

					if (ldc->ldc_error != 0)
					{
						pthread_mutex_unlock(&ldap->ldap_lock);
						return ldc->ldc_error;
					}

					if (ldc->ldc_absent)
					{
						if (exists != NULL)
							*exists = FALSE;

						pthread_mutex_unlock(&ldap->ldap_lock);
						return 0;
					}

					for (c = 0;
					     c < reqnum && c < ldc->ldc_nresults;
					     c++)
					{
						req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
						                               ldc->ldc_results[c],
						                               req[c].dbdata_buflen);
					}

					while (c < reqnum)
						req[c++].dbdata_buflen = 0;

					ldc->ldc_waiters--;

					pthread_cond_signal(&ldc->ldc_cond);

					pthread_mutex_unlock(&ldap->ldap_lock);

					return 0;
				}
			}

			/* add pending info to cache */
			if (ldc == NULL)
			{
				ldc = malloc(sizeof *ldc);
				if (ldc == NULL)
				{
					pthread_mutex_unlock(&ldap->ldap_lock);
					return errno;
				}

				memset(ldc, '\0', sizeof *ldc);

				pthread_cond_init(&ldc->ldc_cond, NULL);
				ldc->ldc_state = DKIMF_DB_CACHE_PENDING;

				status = dkimf_db_put(ldap->ldap_cache,
				                      buf, buflen,
				                      &ldc, sizeof ldc);
				if (status != 0)
				{
					pthread_mutex_unlock(&ldap->ldap_lock);
					return status;
				}
			}

			/* unlock so others can try */
			pthread_mutex_unlock(&ldap->ldap_lock);

			ldc->ldc_error = 0;
		}
# endif /* USE_DB */
#endif /* _FFR_LDAP_CACHING */

		memset(query, '\0', sizeof query);
		memset(filter, '\0', sizeof filter);

		dkimf_db_mkldapquery(ldap->ldap_descr->lud_dn, buf, query,
		                     sizeof query);
		if (ldap->ldap_descr->lud_filter != NULL)
		{
			dkimf_db_mkldapquery(ldap->ldap_descr->lud_filter, buf,
			                     filter, sizeof filter);
		}

		timeout.tv_sec = ldap->ldap_timeout;
		timeout.tv_usec = 0;

		status = ldap_search_ext_s(ld, query,
		                           ldap->ldap_descr->lud_scope,
		                           filter,
		                           ldap->ldap_descr->lud_attrs,
		                           0, NULL, NULL,
		                           &timeout, 0, &result);
		if (status != LDAP_SUCCESS)
		{
			db->db_status = status;
#ifdef _FFR_LDAP_CACHING
# ifdef USE_DB
			ldc->ldc_error = status;
			ldc->ldc_expire = time(NULL) + DKIMF_LDAP_TTL;
			ldc->ldc_state = DKIMF_DB_CACHE_DATA;
			pthread_cond_broadcast(&ldc->ldc_cond);
# endif /* USE_DB */
#endif /* _FFR_LDAP_CACHING */
			pthread_mutex_unlock(&ldap->ldap_lock);
			return status;
		}

		e = NULL;
		if (result != NULL)
			e = ldap_first_entry(ld, result);
		if (e == NULL)
		{
			if (exists != NULL)
				*exists = FALSE;
#ifdef _FFR_LDAP_CACHING
# ifdef USE_DB
			ldc->ldc_absent = TRUE;
			ldc->ldc_state = DKIMF_DB_CACHE_DATA;
			pthread_cond_broadcast(&ldc->ldc_cond);
# endif /* USE_DB */
#endif /* _FFR_LDAP_CACHING */
			pthread_mutex_unlock(&ldap->ldap_lock);
			return 0;
		}

		if (exists != NULL)
			*exists = TRUE;

		for (c = 0; c < reqnum; c++)
		{
			/* bail if we're out of attributes */
			if (ldap->ldap_descr->lud_attrs[c] == NULL)
				break;

			vals = ldap_get_values_len(ld, e,
			                           ldap->ldap_descr->lud_attrs[c]);
			if (vals != NULL && vals[0] != NULL)
			{
				size_t clen;

				clen = MIN(req[c].dbdata_buflen,
				           vals[0]->bv_len);
				memcpy(req[c].dbdata_buffer, vals[0]->bv_val,
				       clen);
				clen = MAX(req[c].dbdata_buflen,
				           vals[0]->bv_len);
				req[c].dbdata_buflen = clen;
				ldap_value_free_len(vals);
			}
		}

		/* tag requests that weren't fulfilled */
		while (c < reqnum)
			req[c++].dbdata_buflen = 0;

		ldap_msgfree(result);
# ifdef _FFR_LDAP_CACHING
#  ifdef USE_DB
		pthread_mutex_lock(&ldap->ldap_lock);

		/* flush anything already cached */
		if (ldc->ldc_nresults != 0)
		{
			for (c = 0; c < ldc->ldc_nresults; c++)
				free(ldc->ldc_results[c]);
			free(ldc->ldc_results);
		}

		/* cache results */
		ldc->ldc_results = malloc(sizeof(char *) * reqnum);
		if (ldc->ldc_results == NULL)
		{
			ldc->ldc_error = errno;
			ldc->ldc_expire = time(NULL) + DKIMF_LDAP_TTL;
			ldc->ldc_state = DKIMF_DB_CACHE_DATA;
			pthread_mutex_unlock(&ldap->ldap_lock);
			return errno;
		}
		ldc->ldc_nresults = reqnum;

		for (c = 0; c < reqnum; c++)
		{
			ldc->ldc_results[c] = strdup(req[c].dbdata_buffer);
			if (ldc->ldc_results[c] == NULL)
			{
				ldc->ldc_error = errno;
				pthread_mutex_unlock(&ldap->ldap_lock);
				return errno;
			}
		}

		ldc->ldc_state = DKIMF_DB_CACHE_DATA;
		ldc->ldc_expire = time(NULL) + DKIMF_LDAP_TTL;

		/* notify waiters */
		pthread_cond_broadcast(&ldc->ldc_cond);
#  endif /* USE_DB */
# endif /* _FFR_LDAP_CACHING */
		pthread_mutex_unlock(&ldap->ldap_lock);
		return 0;
	  }
#endif /* USE_LDAP */

#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		int c;
		int status;
		struct dkimf_db_lua *lua;
		struct dkimf_lua_script_result lres;

		memset(&lres, '\0', sizeof lres);

		lua = (struct dkimf_db_lua *) db->db_data;

		status = dkimf_lua_db_hook(lua->lua_script, (const char *) buf,
		                           &lres);
		if (status != 0)
			return -1;

		if (exists != NULL)
			*exists = (lres.lrs_rcount != 0);

		/* copy results */
		for (c = 0; c < reqnum && c < lres.lrs_rcount; c++)
		{
			req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
			                               lres.lrs_results[c],
			                               req[c].dbdata_buflen);
		}

		/* tag requests that weren't fulfilled */
		while (c < reqnum)
			req[c++].dbdata_buflen = 0;

		/* clean up */
		for (c = 0; c < lres.lrs_rcount; c++)
			free(lres.lrs_results[c]);
		if (lres.lrs_results != NULL)
			free(lres.lrs_results);

		return 0;
	  }
#endif /* USE_LUA */

	  default:
		assert(0);
		return 0;		/* to silence the compiler */
	}

	/* NOTREACHED */
}

/*
**  DKIMF_DB_CLOSE -- close a DB handle
**
**  Parameters:
**  	db -- DB handle to shut down
**
**  Return value:
**  	0 on success, something else on failure
**
**  Notes:
**  	On failure, db has not been freed.  It's not clear what to do in
**  	that case other than get very upset because we probably have a
**  	descriptor that can't be closed.  The subsystem involved should
**  	probably disable itself or otherwise attract attention.
*/

int
dkimf_db_close(DKIMF_DB db)
{
	assert(db != NULL);

	if (db->db_array != NULL)
	{
		int c;

		if ((db->db_iflags & DKIMF_DB_IFLAG_FREEARRAY) != 0)
		{
			for (c = 0; db->db_array[c] != NULL; c++)
				free(db->db_array[c]);
		}
		free(db->db_array);
		db->db_array = NULL;
	}

	if (db->db_lock != NULL &&
	    (db->db_flags & DKIMF_DB_FLAG_MAKELOCK) != 0)
	{
		pthread_mutex_destroy(db->db_lock);
		free(db->db_lock);
	}

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
		if (db->db_handle != NULL)
			dkimf_db_list_free(db->db_handle);
		free(db);
		return 0;

	  case DKIMF_DB_TYPE_REFILE:
		if (db->db_handle != NULL)
			dkimf_db_relist_free(db->db_handle);
		free(db);
		return 0;

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
	  {
		int status;

# if DB_VERSION_CHECK(2,0,0)
		if (db->db_cursor != NULL)
			((DBC *) (db->db_cursor))->c_close((DBC *) db->db_cursor);
# endif /* DB_VERSION_CHECK(2,0,0) */
		status = DKIMF_DBCLOSE((DB *) (db->db_handle));
		if (status != 0)
			db->db_status = status;
		else
			free(db);

		return status;
	  }
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
		(void) odbx_finish((odbx_t *) db->db_handle);
		free(db->db_data);
		free(db);
		return 0;
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		struct dkimf_db_ldap *ldap;

		ldap = (struct dkimf_db_ldap *) db->db_data;

		ldap_unbind_ext((LDAP *) db->db_handle, NULL, NULL);
		pthread_mutex_destroy(&ldap->ldap_lock);
# ifdef _FFR_LDAP_CACHING
#  ifdef USE_DB
		if (ldap->ldap_cache != NULL)
		{
			_Bool first = TRUE;
			int c;
			int status;
			struct dkimf_db_ldap_cache *ldc;
			struct dkimf_db_data dbd;

			dbd.dbdata_buffer = (char *) &ldc;
			dbd.dbdata_buflen = sizeof ldc;
			dbd.dbdata_flags = DKIMF_DB_DATA_BINARY;

			for (;;)
			{
				status = dkimf_db_walk(ldap->ldap_cache, first,
				                       NULL, NULL, &dbd, 1);

				if (status != 0)
					break;

				for (c = 0; c < ldc->ldc_nresults; c++)
					free(ldc->ldc_results[c]);
				free(ldc->ldc_results);
				free(ldc);

				first = FALSE;
			}
			
			(void) dkimf_db_close(ldap->ldap_cache);
		}
#  endif /* USE_DB */
# endif /* _FFR_LDAP_CACHING */
		(void) ldap_free_urldesc(ldap->ldap_descr);
		free(db->db_data);
		free(db);
		return 0;
	  }
#endif /* USE_LDAP */

#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		struct dkimf_db_lua *lua;

		lua = (struct dkimf_db_lua *) db->db_data;

		free(lua->lua_script);
		free(db->db_data);
		free(db);
		return 0;
	  }
#endif /* USE_LUA */

	  default:
		assert(0);
		return -1;
	}
}

/*
**  DKIMF_DB_STRERROR -- obtain an error string
**
**  Parameters:
**  	db -- DKIMF_DB handle of interest
**  	err -- error buffer
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	Bytes written to "err".
*/

int
dkimf_db_strerror(DKIMF_DB db, char *err, size_t errlen)
{
	assert(db != NULL);
	assert(err != NULL);

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
		return strlcpy(err, strerror(db->db_status), errlen);

	  case DKIMF_DB_TYPE_REFILE:
		return regerror(db->db_status, db->db_data, err, errlen);

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
		return strlcpy(err, DB_STRERROR(db->db_status), errlen);
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
		return strlcpy(err, odbx_error((odbx_t *) db->db_handle,
		                               db->db_status), errlen);
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
		return strlcpy(err, ldap_err2string(db->db_status), errlen);
#endif /* USE_LDAP */

#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		struct dkimf_db_lua *lua;

		lua = (struct dkimf_db_lua *) db->db_data;
		if (lua->lua_error != NULL)
			return strlcpy(err, lua->lua_error, errlen);
		else
			return 0;
	  }
#endif /* USE_LUA */

	  default:
		assert(0);
		return -1;		/* to silence the compiler */
	}

	/* NOTREACHED */
}

/*
**  DKIMF_DB_WALK -- walk a database
**
**  Parameters:
**  	db -- database
**  	first -- get first record?
**  	key -- buffer to receive the key
**  	keylen -- bytes available at "key" (updated)
**  	req -- buffers to receive the data ("requests")
**  	reqnum -- number of requests
**
**  Return value:
**  	0 -- record returned
**  	1 -- no more records
**  	-1 -- error
*/

int
dkimf_db_walk(DKIMF_DB db, _Bool first, void *key, size_t *keylen,
              DKIMF_DBDATA req, unsigned int reqnum)
{
	assert(db != NULL);

	if ((key != NULL && keylen == NULL) ||
	    (key == NULL && keylen != NULL))
		return -1;

	if (db->db_type == DKIMF_DB_TYPE_REFILE ||
	    db->db_type == DKIMF_DB_TYPE_LUA)
		return -1;

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_CSL:
	  case DKIMF_DB_TYPE_FILE:
	  {
		struct dkimf_db_list *list;

		if (first)
			list = (struct dkimf_db_list *) db->db_handle;
		else
			list = (struct dkimf_db_list *) db->db_cursor;

		if (list == NULL)
			return 1;

		if (key != NULL)
			*keylen = strlcpy(key, list->db_list_key, *keylen);

		if (reqnum != 0)
		{
			if (list->db_list_value != NULL)
			{
				if (dkimf_db_datasplit(list->db_list_value,
				                       strlen(list->db_list_value),
				                       req, reqnum) != 0)
                                        return -1;
			}
		}

		list = list->db_list_next;
		db->db_cursor = list;

		return 0;
	  }

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
	  {
		int status = 0;
		DB *bdb;
		DBT k;
		DBT d;
# if DB_VERSION_CHECK(2,0,0)
		DBC *dbc;
# endif /* DB_VERSION_CHECK(2,0,0) */
		char databuf[BUFRSZ + 1];

		bdb = (DB *) db->db_handle;

# if DB_VERSION_CHECK(2,0,0)
		/* establish a cursor if needed */
		dbc = db->db_cursor;
		if (dbc == NULL)
		{
			status = bdb->cursor(bdb, NULL, &dbc, 0);
			if (status != 0)
			{
				db->db_status = status;
				return -1;
			}

			db->db_cursor = dbc;
		}
# endif /* DB_VERSION_CHECK(2,0,0) */

		memset(&k, '\0', sizeof k);
		memset(&d, '\0', sizeof d);

# if DB_VERSION_CHECK(2,0,0)
		k.data = (void *) key;
		k.flags = DB_DBT_USERMEM;
		k.ulen = (keylen != NULL ? *keylen : 0);
# endif /* DB_VERSION_CHECK(2,0,0) */

# if DB_VERSION_CHECK(2,0,0)
		d.data = databuf;
		d.flags = DB_DBT_USERMEM;
		d.ulen = sizeof databuf;
# endif /* DB_VERSION_CHECK(2,0,0) */

# if DB_VERSION_CHECK(2,0,0)
		status = dbc->c_get(dbc, &k, &d, first ? DB_FIRST : DB_NEXT);
# else /* DB_VERSION_CHECK(2,0,0) */
		status = bdb->seq(bdb, &k, &d, first ? R_FIRST : R_NEXT);
# endif /* DB_VERSION_CHECK(2,0,0) */
		if (status == DB_NOTFOUND)
		{
			return 1;
		}
		else if (status != 0)
		{
			db->db_status = status;
			return -1;
		}
		else
		{
# if !DB_VERSION_CHECK(2,0,0)
			if (key != NULL)
			{
				memcpy(key, k.data, MIN(k.size, *keylen));
				*keylen = MIN(k.size, *keylen);
			}

			if (reqnum != 0)
			{
				if (dkimf_db_datasplit(d.data, d.size,
				                       req, reqnum) != 0)
                                        return -1;
			}
# else /* DB_VERSION_CHECK(2,0,0) */
			if (reqnum != 0)
			{
				if (dkimf_db_datasplit(databuf, sizeof databuf,
				                       req, reqnum) != 0)
                                        return -1;
			}

			if (keylen != NULL)
				*keylen = k.size;
# endif /* DB_VERSION_CHECK(2,0,0) */

			return 0;
		}
	  }
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
	  {
		int err;
		int fields;
		odbx_result_t *result;
		struct dkimf_db_dsn *dsn;
		char query[BUFRSZ];

		dsn = (struct dkimf_db_dsn *) db->db_data;
		result = (odbx_result_t *) db->db_cursor;

		/* purge old results cursor if known */
		if (result != NULL && first)
		{
			(void) odbx_result_finish(result);
			result = NULL;
		}
		
		/* run a query and start results cursor if needed */
		if (result == NULL)
		{
			char query[BUFRSZ];

			snprintf(query, sizeof query, "SELECT %s,%s FROM %s",
			         dsn->dsn_keycol, dsn->dsn_datacol,
			         dsn->dsn_table);

			err = odbx_query((odbx_t *) db->db_handle, query, 0);
			if (err < 0)
			{
				db->db_status = err;
				return -1;
			}

			err = odbx_result((odbx_t *) db->db_handle,
			                  &result, NULL, 0);
			if (err < 0)
			{
				(void) odbx_result_finish(result);
				db->db_status = err;
				return -1;
			}

			db->db_cursor = result;
		}

		err = odbx_row_fetch(result);
		if (err < 0)
		{
			(void) odbx_result_finish(result);
			db->db_cursor = NULL;
			db->db_status = err;
			return -1;
		}

		if (err == ODBX_RES_DONE)
			return 1;

		fields = odbx_column_count(result);
		if (fields == 0)
		{
			/* query returned no columns somehow */
			(void) odbx_result_finish(result);
			db->db_cursor = NULL;
			return -1;
		}

		if (key != NULL && keylen != NULL)
		{
			*keylen = strlcpy(key,
			                  (char *) odbx_field_value(result, 0),
		                          *keylen);
		}

		if (reqnum != 0)
		{
			int c;

			for (c = 0; c < reqnum; c++)
			{
				if (c >= fields)
				{
					req[c].dbdata_buflen = 0;
				}
				else
				{
					char *val;

					val = (char *) odbx_field_value(result,
					                                c + 1);

					req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
					                               val,
					                               req[c].dbdata_buflen);
				}
			}
		}

		return 0;
	  }
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		int c;
		int status;
		char *p;
		LDAP *ld;
		LDAPMessage *result;
		LDAPMessage *e;
		struct dkimf_db_ldap *ldap;
		struct berval **vals;
		char filter[BUFRSZ];
		char query[BUFRSZ];
		struct timeval timeout;

		ld = (LDAP *) db->db_handle;
		ldap = (struct dkimf_db_ldap *) db->db_data;
		result = (LDAPMessage *) db->db_cursor;

		pthread_mutex_lock(&ldap->ldap_lock);

		if (first)
		{
			if (result != NULL)
			{
				ldap_msgfree(result);
				db->db_cursor = NULL;
				db->db_entry = NULL;
			}

			memset(query, '\0', sizeof query);
			memset(filter, '\0', sizeof filter);

			dkimf_db_mkldapquery(ldap->ldap_descr->lud_dn, "",
			                     query, sizeof query);
			dkimf_db_mkldapquery(ldap->ldap_descr->lud_filter, "*",
			                     filter, sizeof filter);

			timeout.tv_sec = ldap->ldap_timeout;
			timeout.tv_usec = 0;

			status = ldap_search_ext_s(ld, query,
			                           ldap->ldap_descr->lud_scope,
			                           filter,
			                           ldap->ldap_descr->lud_attrs,
			                           0, NULL, NULL,
			                           &timeout, 0, &result);

			if (status != LDAP_SUCCESS)
			{
				db->db_status = status;
				pthread_mutex_unlock(&ldap->ldap_lock);
				return -1;
			}

			db->db_cursor = (void *) result;

			e = ldap_first_entry(ld, result);
			if (e == NULL)
			{
				pthread_mutex_unlock(&ldap->ldap_lock);
				return 1;
			}

			db->db_entry = (void *) e;
		}
		else
		{
			e = ldap_next_entry(ld, (LDAPMessage *) db->db_entry);
			if (e == NULL)
			{
				pthread_mutex_unlock(&ldap->ldap_lock);
				return 1;
			}

			db->db_entry = (void *) e;
		}

		p = ldap_get_dn(ld, e);
		if (p != NULL)
		{
#if LDAP_API_VERSION < 3001
			LDAPDN *dn = NULL;
#else /* LDAP_API_VERSION < 3001 */
			LDAPDN dn = NULL;
#endif /* LDAP_API_VERSION < 3001 */
			LDAPRDN rdn = NULL;
			LDAPAVA *ava = NULL;

			if (ldap_str2dn(p, &dn, 0) != 0)
			{
				ldap_memfree(p);
				pthread_mutex_unlock(&ldap->ldap_lock);
				return 1;
			}

			if (dn != NULL)
			{
#if LDAP_API_VERSION < 3001
				rdn = dn[0][0][0];
#else /* LDAP_API_VERSION < 3001 */
				rdn = dn[0];
#endif /* LDAP_API_VERSION < 3001 */
				ava = rdn[0];
			}

			if (key != NULL && keylen != NULL && dn != NULL &&
			    ava->la_value.bv_len != 0)
			{
				*keylen = strlcpy(key,
				                  ava->la_value.bv_val,
				                  *keylen);
			}
			else if (keylen != NULL)
			{
				*keylen = 0;
			}

			ldap_dnfree(dn);
			ldap_memfree(p);
		}

		for (c = 0; c < reqnum; c++)
		{
			vals = ldap_get_values_len(ld, e,
			                           ldap->ldap_descr->lud_attrs[c]);
			if (vals != NULL && vals[0]->bv_len != 0)
			{
				size_t clen;

				clen = MIN(req[c].dbdata_buflen,
				           vals[0]->bv_len);
				memcpy(req[c].dbdata_buffer, vals[0]->bv_val,
				       clen);
				clen = MAX(req[c].dbdata_buflen,
				           vals[0]->bv_len);
				req[c].dbdata_buflen = clen;
				ldap_value_free_len(vals);
			}
			else
			{
				req[c].dbdata_buflen = 0;
			}
		}

		pthread_mutex_unlock(&ldap->ldap_lock);

		return 0;
	  }
#endif /* USE_LDAP */

	  default:
		assert(0);
		return -1;		/* to silence compiler warnings */
	}
}

/*
**  DKIMF_DB_MKARRAY -- make a (char *) array of DB contents
**
**  Parameters:
**  	db -- a DKIMF_DB handle
**  	a -- array (returned)
**
**  Return value:
**  	Length of the created array, or -1 on error/empty.
*/

int
dkimf_db_mkarray(DKIMF_DB db, char ***a)
{
	char **out;

	assert(db != NULL);
	assert(a != NULL);

	if (db->db_type == DKIMF_DB_TYPE_REFILE ||
	    db->db_type == DKIMF_DB_TYPE_LUA)
		return -1;

#ifdef USE_DB
	if (db->db_type != DKIMF_DB_TYPE_BDB && db->db_nrecs == 0)
		return 0;
#endif /* USE_DB */

	if ((db->db_type == DKIMF_DB_TYPE_FILE ||
	     db->db_type == DKIMF_DB_TYPE_CSL) &&
	    db->db_array != NULL)
	{
		*a = db->db_array;
		return db->db_nrecs;
	}

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
	  {
		int c = 0;
		struct dkimf_db_list *cur;

		out = (char **) malloc(sizeof(char *) * (db->db_nrecs + 1));
		if (out != NULL)
		{
			cur = db->db_handle;
			for (c = 0; c < db->db_nrecs; c++)
			{
				out[c] = cur->db_list_key;
				cur = cur->db_list_next;
			}

			out[c] = NULL;
		}

		db->db_array = out;

		*a = out;

		return c;
	  }

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
#endif /* USE_DB */
#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
#endif /* USE_ODBX */
#if defined(USE_DB) || defined(USE_ODBX)
	  {
		int c;
		int nr = 0;
		int na = 0;
		int status;
		size_t keylen;
		char keybuf[BUFRSZ + 1];

		if (db->db_array != NULL)
		{
			for (c = 0; db->db_array[c] != NULL; c++)
				free(db->db_array[c]);
			free(db->db_array);
			db->db_array = NULL;
		}

		status = 0;
		while (status == 0)
		{
			memset(keybuf, '\0', sizeof keybuf);

			keylen = sizeof keybuf - 1;
			status = dkimf_db_walk(db, (nr == 0),
			                       keybuf, &keylen, NULL, 0);

			if (nr == 0)
			{
				out = (char **) malloc(sizeof(char *) * DEFARRAYSZ);
				if (out == NULL)
					return -1;

				out[0] = strdup(keybuf);
				if (out[0] == NULL)
				{
					free(out);
					return -1;
				}

				na = DEFARRAYSZ;
				nr = 1;
				out[nr] = NULL;
			}
			else
			{
				if (nr + 1 == na)
				{
					int newsz;
					char **newout;

					newsz = na * 2;

					newout = (char **) realloc(out, sizeof (char *) * newsz);
					if (newout == NULL)
					{
						for (c = 0; c < nr; c++)
							free(out[c]);
						free(out);
						return -1;
					}

					na = newsz;
				}

				out[nr] = strdup(keybuf);
				if (out[nr] == NULL)
				{
					for (c = 0; c < nr; c++)
						free(out[c]);
					free(out);
					return -1;
				}

				nr++;
				out[nr] = NULL;
			}
		}

		if (status == -1)
		{
			for (c = 0; c < nr; c++)
				free(out[c]);
			free(out);
			return -1;
		}

		db->db_array = out;
		db->db_iflags |= DKIMF_DB_IFLAG_FREEARRAY;
		*a = out;
		return nr;
	  }
#endif /* defined(USE_DB) || defined(USE_ODBX) */

	  default:
		return -1;
	}
}

/*
**  DKIMF_DB_REWALK -- walk a regular expression DB looking for matches
**
**  Parameters:
**  	db -- database of interest
**  	str -- string to match
**  	req -- list of data requests
**  	reqnum -- number of data requests
**  	ctx -- context pointer (updated) (may be NULL)
**
**  Return value:
**  	-1 -- error
**  	0 -- match found
**  	1 -- no match found
*/

int
dkimf_db_rewalk(DKIMF_DB db, char *str, DKIMF_DBDATA req, unsigned int reqnum,
                void **ctx)
{
	int status;
	struct dkimf_db_relist *re;

	assert(db != NULL);
	assert(str != NULL);

	if (db->db_type != DKIMF_DB_TYPE_REFILE)
		return -1;

	if (ctx != NULL && *ctx != NULL)
	{
		re = (struct dkimf_db_relist *) *ctx;
		if (re->db_relist_next == NULL)
			return 1;
		else
			re = re->db_relist_next;
	}
	else
	{
		re = (struct dkimf_db_relist *) db->db_handle;
	}

	while (re != NULL)
	{
		status = regexec(&re->db_relist_re, str, 0, NULL, 0);

		if (status == 0)
		{
			if (ctx != NULL)
				*ctx = re;

			if (dkimf_db_datasplit(re->db_relist_data,
			                      strlen(re->db_relist_data),
			                      req, reqnum) != 0)
			{
                                return -1;
			}
			else
			{
                        	return 0;
			}
		}
		else if (status != REG_NOMATCH)
		{
			return -1;
		}

		re = re->db_relist_next;
	}

	return 1;
}

/*
**  DKIMF_DB_FD -- retrieve a file descriptor associated with a database
**
**  Parameters:
**  	db -- DKIMF_DB handle
**
**  Return value:
**  	File descriptor associated with the DB, or -1 if none.
*/

int
dkimf_db_fd(DKIMF_DB db)
{
	int fd = -1;

#ifdef USE_DB
	if (db->db_type == DKIMF_DB_TYPE_BDB)
	{
		DB *bdb;

		bdb = (DB *) db->db_handle;

# if DB_VERSION_CHECK(2,0,0)
		(void) bdb->fd(bdb, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
		fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */
	}
#endif /* USE_DB */

	return fd;
}

/*
**  DKIMF_DB_SET_LDAP_PARAM -- set an LDAP parameter
**
**  Parameters:
**  	param -- parameter code to set
**  	str -- new string pointer value
**
**  Return value:
**  	None.
*/

void
dkimf_db_set_ldap_param(int param, char *str)
{
	assert(param >= 0 && param <= DKIMF_LDAP_PARAM_MAX);

	dkimf_db_ldap_param[param] = str;
}
