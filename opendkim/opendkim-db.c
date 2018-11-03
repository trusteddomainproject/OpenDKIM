/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2015, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! _REENTRANT */

/* system includes */
#include <sys/types.h>
#include <sys/uio.h>
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
#include <netdb.h>

/* libopendkim includes */
#include <dkim.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* repute includes */
#ifdef _FFR_REPUTATION
# include <repute.h>
#endif /* _FFR_REPUTATION */

/* opendkim includes */
#include "util.h"
#ifdef OPENDKIM_DB_ONLY
# undef USE_LDAP
# undef USE_SASL
# undef USE_ODBX
# undef USE_LUA
# undef _FFR_SOCKETDB
#endif /* OPENDKIM_DB_ONLY */
#include "opendkim-db.h"
#ifdef USE_LUA
# include "opendkim-lua.h"
#endif /* USE_LUA */
#include "opendkim.h"

/* various DB library includes */
#ifdef _FFR_SOCKETDB
# include <sys/socket.h>
# include <sys/un.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif /* _FFR_SOCKETDB */
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
#ifdef USE_LIBMEMCACHED
# include <libmemcached/memcached.h>
#endif /* USE_LIBMEMCACHED */
#ifdef USE_MDB
# include <lmdb.h>
#endif /* USE_MDB */
#ifdef USE_ERLANG
# include <sys/time.h>
# include <erl_interface.h>
# include <ei.h>
#endif /* USE_ERLANG */

/* macros */
#define	BUFRSZ			1024
#define	DEFARRAYSZ		16
#ifdef _FFR_DB_HANDLE_POOLS
# define DEFPOOLMAX		10
#endif /* _FFR_DB_HANDLE_POOLS */
#define DKIMF_DB_DEFASIZE	8
#define DKIMF_DB_MODE		0644
#define DKIMF_LDAP_MAXURIS	8
#define DKIMF_LDAP_DEFTIMEOUT	5
#ifdef _FFR_LDAP_CACHING
# define DKIMF_LDAP_TTL		600
#endif /* _FFR_LDAP_CACHING */
#ifdef _FFR_SOCKETDB
# define DKIMF_SOCKET_TIMEOUT	5
#endif /* _FFR_SOCKETDB */

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

#define STRORNULL(x)	((x)[0] == '\0' ? NULL : (x))

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
	const char *		dsn_filter;
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
	size_t			lua_scriptlen;
	char *			lua_error;
};
#endif /* USE_LUA */

#ifdef _FFR_SOCKETDB
struct dkimf_db_socket
{
	int			sockdb_fd;
	struct dkimf_dstring *	sockdb_buf;
};
#endif /* _FFR_SOCKETDB */

#ifdef USE_MDB
struct dkimf_db_mdb
{
	MDB_env *		mdb_env;
	MDB_txn *		mdb_txn;
	MDB_dbi			mdb_dbi;
};
#endif /* USE_MDB */

#ifdef USE_ERLANG
struct dkimf_db_erlang
{
	char *			erlang_nodes;
	char *			erlang_module;
	char *			erlang_function;
	char *			erlang_cookie;
};
#endif /* USE_ERLANG */

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
#ifdef USE_LIBMEMCACHED
	{ "memcache",		DKIMF_DB_TYPE_MEMCACHE },
#endif /* USE_LIBMEMCACHED */
#ifdef _FFR_REPUTATION
	{ "repute",		DKIMF_DB_TYPE_REPUTE },
#endif /* _FFR_REPUTATION */
#ifdef _FFR_SOCKETDB
	{ "socket",		DKIMF_DB_TYPE_SOCKET },
#endif /* _FFR_SOCKETDB */
#ifdef USE_MDB
	{ "mdb",		DKIMF_DB_TYPE_MDB },
#endif /* USE_MDB */
#ifdef USE_ERLANG
	{ "erlang",		DKIMF_DB_TYPE_ERLANG },
#endif /* USE_ERLANG */
	{ NULL,			DKIMF_DB_TYPE_UNKNOWN },
};

static char *dkimf_db_ldap_param[DKIMF_LDAP_PARAM_MAX + 1];

#ifdef _FFR_DB_HANDLE_POOLS
struct handle_pool
{
	u_int		hp_dbtype;
	u_int		hp_max;
	u_int		hp_alloc;
	u_int		hp_asize;
	u_int		hp_count;
	void *		hp_hdata;
	void **		hp_handles;
	pthread_mutex_t	hp_lock;
	pthread_cond_t	hp_signal;
};
#endif /* _FFR_DB_HANDLE_POOLS */

/* globals */
static unsigned int gflags = 0;

#ifdef _FFR_DB_HANDLE_POOLS
/*
**  DKIMF_DB_HP_NEW -- create a handle pool
**
**  Parameters:
**  	type -- DB type
**  	max -- maximum pool size
**  	hdata -- data needed to make new handles
**
**  Return value:
**  	Pointer to a newly-allocated handle pool, or NULL on error.
*/

static struct handle_pool *
dkimf_db_hp_new(u_int type, u_int max, void *hdata)
{
	struct handle_pool *new;

	new = (struct handle_pool *) malloc(sizeof *new);
	if (new != NULL)
	{
		new->hp_alloc = 0;
		new->hp_asize = 0;
		new->hp_count = 0;
		new->hp_dbtype = type;
		new->hp_handles = NULL;
		new->hp_hdata = hdata;
		new->hp_max = max;
		pthread_mutex_init(&new->hp_lock, NULL);
		pthread_cond_init(&new->hp_signal, NULL);
	}

	return new;
}

/*
**  DKIMF_DB_HP_FREE -- free a handle pool
**
**  Parameters:
**  	pool -- bool to free up
**
**  Return value:
**  	None.
*/

static void
dkimf_db_hp_free(struct handle_pool *pool)
{
	u_int c;

	assert(pool != NULL);

	for (c = 0; c < pool->hp_count; c++)
	{
		switch (pool->hp_dbtype)
		{
#ifdef USE_ODBX
		  case DKIMF_DB_TYPE_DSN:
		  {
			odbx_t *odbx;

			odbx = (odbx_t *) pool->hp_handles[c];

			(void) odbx_unbind(odbx);
			(void) odbx_finish(odbx);
			free(odbx);

			break;
		  }
#endif /* USE_ODBX */

		  default:
			break;
		}
	}

	pthread_mutex_destroy(&pool->hp_lock);
	pthread_cond_destroy(&pool->hp_signal);
	free(pool->hp_handles);
	free(pool);
}

/*
**  DKIMF_DB_HP_GET -- get a handle from a handle pool
**
**  Parameters:
**  	pool -- pool from which to get a handle
**  	err -- error code (returned)
**
**  Return value:
**  	A handle appropriate to the associated DB type that is not currently
**  	in use by another thread, or NULL on error.
*/

static void *
dkimf_db_hp_get(struct handle_pool *pool, int *err)
{
	void *ret;

	assert(pool != NULL);

	pthread_mutex_lock(&pool->hp_lock);

	for (;;)
	{
		/* if one is available, return it */
		if (pool->hp_count > 0)
		{
			ret = pool->hp_handles[0];

			if (pool->hp_count > 1)
			{
				memmove(&pool->hp_handles[0],
				        &pool->hp_handles[1],
				        sizeof(void *) * (pool->hp_count - 1));
			}

			pool->hp_count--;

			pthread_mutex_unlock(&pool->hp_lock);

			return ret;
		}

		/* if we can allocate one, do so */
		if (pool->hp_alloc <= pool->hp_max)
		{
			switch (pool->hp_dbtype)
			{
#ifdef USE_ODBX
			  case DKIMF_DB_TYPE_DSN:
			  {
				int dberr;
				odbx_t *odbx;
				struct dkimf_db_dsn *dsn;

				dsn = (struct dkimf_db_dsn *) pool->hp_hdata;

				dberr = odbx_init(&odbx,
				                  STRORNULL(dsn->dsn_backend),
				                  STRORNULL(dsn->dsn_host),
				                  STRORNULL(dsn->dsn_port));

				if (dberr < 0)
				{
					if (err != NULL)
						*err = dberr;

					(void) odbx_finish(odbx);
					pthread_mutex_unlock(&pool->hp_lock);

					return NULL;
				}

				dberr = odbx_bind(odbx,
				                        STRORNULL(dsn->dsn_dbase),
				                        STRORNULL(dsn->dsn_user),
				                        STRORNULL(dsn->dsn_password),
				                        ODBX_BIND_SIMPLE);
				if (dberr < 0)
				{
					if (err != NULL)
						*err = dberr;

					(void) odbx_finish(odbx);
					pthread_mutex_unlock(&pool->hp_lock);

					return NULL;
				}

				ret = odbx;

				break;
			  }
#endif /* USE_ODBX */

			  default:
				assert(0);
				break;
			}

			pool->hp_alloc++;

			pthread_mutex_unlock(&pool->hp_lock);

			return ret;
		}

		/* already full; wait for one */
		pthread_cond_wait(&pool->hp_signal, &pool->hp_lock);
	}
}

/*
**  DKIMF_DB_HP_DEAD -- report that a handle found in the pool was dead
**
**  Parameters:
**  	pool -- handle pool to be updated
**
**  Return value:
**  	None.
**
**  Notes:
**  	The caller is expected to identify a dead handle and deallocate it.
*/

static void
dkimf_db_hp_dead(struct handle_pool *pool)
{
	assert(pool != NULL);

	pthread_mutex_lock(&pool->hp_lock);
	pool->hp_alloc--;
	pthread_cond_signal(&pool->hp_signal);
	pthread_mutex_unlock(&pool->hp_lock);
}

/*
**  DKIMF_DB_HP_PUT -- put a handle back into a handle pool after use
**
**  Parameters:
**  	pool -- pool from which to get a handle
**  	handle -- handle being returned
**
**  Return value:
**  	None.
*/

static void
dkimf_db_hp_put(struct handle_pool *pool, void *handle)
{
	assert(pool != NULL);
	assert(handle != NULL);

	pthread_mutex_lock(&pool->hp_lock);

	/* need to grow the array? */
	if (pool->hp_asize == pool->hp_count)
	{
		u_int newasz;

		if (pool->hp_asize == 0)
		{
			newasz = DKIMF_DB_DEFASIZE;
			pool->hp_handles = (void **) malloc(newasz * sizeof(void *));
			assert(pool->hp_handles != NULL);
		}
		else
		{
			void **newa;

			newasz = pool->hp_asize * 2;
			newa = (void **) realloc(pool->hp_handles,
			                         newasz * sizeof(void *));
			assert(newa != NULL);
			pool->hp_handles = newa;
		}

		pool->hp_asize = newasz;
	}

	/* append it */
	pool->hp_handles[pool->hp_count] = handle;

	/* increment the count */
	pool->hp_count++;

	/* signal any waiters */
	pthread_cond_signal(&pool->hp_signal);

	/* all done */
	pthread_mutex_unlock(&pool->hp_lock);
}

#endif /* _FFR_DB_HANDLE_POOLS */

/*
**  DKIMF_DB_FLAGS -- set global flags
**
**  Parameters:
**  	flags -- new global flag mask
**
**  Return value:
**  	None.
*/

void
dkimf_db_flags(unsigned int flags)
{
	gflags = flags;
}

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
		if (interact->result == NULL)
			interact->len = 0;
		else
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

#ifdef USE_ODBX
/*
**  DKIMF_DB_HEXDIGIT -- convert a hex digit to decimal value
**
**  Parameters:
**  	c -- input character
**
**  Return value:
**  	Converted value, or 0 on error.
*/

static int
dkimf_db_hexdigit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'f' + 10;
	else
		return 0;
}
#endif /* USE_ODBX */

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
	if (ridx < reqnum)
	{
		int c;

		for (c = ridx; c < reqnum; c++)
		{
			if ((req[c].dbdata_flags & DKIMF_DB_DATA_OPTIONAL) == 0)
				ret = -1;
			req[c].dbdata_buflen = (size_t) -1;
		}
	}

        return ret;
}

#ifdef USE_LDAP
# define ISRFC2254CHR(q)	((q) == 0x2a ||	\
				 (q) == 0x28 || \
				 (q) == 0x29 || \
				 (q) == 0x5c || \
				 (q) == 0x00)

# define ADDRFC2254CHR(x, y, z)	{ \
					*(x)++ = '\\'; \
					if ((y) > (x)) \
					{ \
						(x) += snprintf((x), \
						                (y) - (x), \
						                "%02x", \
						                (z)); \
					} \
				}

/*
**  DKIMF_DB_MKLDAPQUERY -- generate an LDAP query
**
**  Parameters:
**  	buf -- parameter (the actual query)
**  	query -- query string (a domain name?)
**  	out -- outbut buffer
**  	outlen -- size of "out"
**
**  Return value:
**  	None.
**
**  Notes:
**  	Expands "$d" and "$D" as defined in opendkim.conf(5).
** 
**  	Should report overflows.
*/

static void
dkimf_db_mkldapquery(char *buf, char *query, _Bool raw,
                     char *out, size_t outlen)
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
				{
					if (ISRFC2254CHR(*q) && !raw)
					{
						ADDRFC2254CHR(o, oend, *q);
					}
					else
					{
						*o++ = *q;
					}
				}
			}
			else if (*p == 'D')
			{
				for (q = query; o <= oend && q <= qend; q++)
				{
					if (q == query)
					{
						o += strlcpy(o, "dc=",
						             oend - o);
					}

					if (*q == '.')
					{
						o += strlcpy(o, ",dc=",
						             oend - o);
					}
					else if (ISRFC2254CHR(*q))
					{
						ADDRFC2254CHR(o, oend, *q);
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

#ifdef USE_ODBX
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
		    *p == '?')
			return p;

		if (*p == '=' &&
		    (!isxdigit(*(p + 1)) ||
		     !isxdigit(*(p + 2))))
			return p;
	}

	return NULL;
}
#endif /* USE_ODBX */

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

#ifdef USE_LDAP
/*
**  DKIMF_DB_OPEN_LDAP -- attempt to contact an LDAP server
**
**  Parameters:
**  	ld -- LDAP handle (updated on success)
**  	ldap -- local LDAP data
**
**  Return value:
**  	An LDAP_* constant.
*/

int
dkimf_db_open_ldap(LDAP **ld, struct dkimf_db_ldap *ldap, char **err)
{
	int v = LDAP_VERSION3;
	int n;
	int lderr;
	char *q;
	char *r;
	char *u;
	struct timeval timeout;

	assert(ld != NULL);
	assert(ldap != NULL);

	/* create LDAP handle */
	lderr = ldap_initialize(ld, ldap->ldap_urilist);
	if (lderr != LDAP_SUCCESS)
	{
		if (err != NULL)
			*err = ldap_err2string(lderr);
		return lderr;
	}

	/* set LDAP version */
	lderr = ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &v);
	if (lderr != LDAP_OPT_SUCCESS)
	{
		if (err != NULL)
			*err = ldap_err2string(lderr);
		ldap_unbind_ext(*ld, NULL, NULL);
		*ld = NULL;
		return lderr;
	}

	/* enable auto-restarts */
	lderr = ldap_set_option(*ld, LDAP_OPT_RESTART, LDAP_OPT_ON);
	if (lderr != LDAP_OPT_SUCCESS)
	{
		if (err != NULL)
			*err = ldap_err2string(lderr);
		ldap_unbind_ext(*ld, NULL, NULL);
		*ld = NULL;
		return lderr;
	}

	/* request timeouts */
	q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_TIMEOUT];
	timeout.tv_sec = DKIMF_LDAP_DEFTIMEOUT;
	timeout.tv_usec = 0;
	if (q != NULL)
	{
		errno = 0;
		timeout.tv_sec = strtoul(q, &r, 10);
		if (errno == ERANGE)
			timeout.tv_sec = DKIMF_LDAP_DEFTIMEOUT;
	}

	lderr = ldap_set_option(*ld, LDAP_OPT_TIMEOUT, &timeout);
	if (lderr != LDAP_OPT_SUCCESS)
	{
		if (err != NULL)
			*err = ldap_err2string(lderr);
		ldap_unbind_ext(*ld, NULL, NULL);
		*ld = NULL;
		return lderr;
	}

	/* request keepalive */
	q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_KA_IDLE];
	if (q != NULL)
	{
		errno = 0;
		n = strtoul(q, &r, 10);
		if (errno != ERANGE)
		{
			lderr = ldap_set_option(*ld, LDAP_OPT_X_KEEPALIVE_IDLE,
			                        &n);
			if (lderr != LDAP_OPT_SUCCESS)
			{
				if (err != NULL)
					*err = ldap_err2string(lderr);
				ldap_unbind_ext(*ld, NULL, NULL);
				*ld = NULL;
				return lderr;
			}
		}
	}

	q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_KA_PROBES];
	if (q != NULL)
	{
		errno = 0;
		n = strtoul(q, &r, 10);
		if (errno != ERANGE)
		{
			lderr = ldap_set_option(*ld,
			                        LDAP_OPT_X_KEEPALIVE_PROBES,
			                        &n);
			if (lderr != LDAP_OPT_SUCCESS)
			{
				if (err != NULL)
					*err = ldap_err2string(lderr);
				ldap_unbind_ext(*ld, NULL, NULL);
				*ld = NULL;
				return lderr;
			}
		}
	}

	q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_KA_INTERVAL];
	if (q != NULL)
	{
		errno = 0;
		n = strtoul(q, &r, 10);
		if (errno != ERANGE)
		{
			lderr = ldap_set_option(*ld,
			                        LDAP_OPT_X_KEEPALIVE_INTERVAL,
			                        &n);
			if (lderr != LDAP_OPT_SUCCESS)
			{
				if (err != NULL)
					*err = ldap_err2string(lderr);
				ldap_unbind_ext(*ld, NULL, NULL);
				*ld = NULL;
				return lderr;
			}
		}
	}

	/* attempt TLS if requested, except for ldaps */
	q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_USETLS];
	if (q != NULL && (*q == 'y' || *q == 'Y') &&
	    strcasecmp(ldap->ldap_descr->lud_scheme, "ldaps") != 0)
	{
		lderr = ldap_start_tls_s(*ld, NULL, NULL);
		if (lderr != LDAP_SUCCESS)
		{
			if (err != NULL)
				*err = ldap_err2string(lderr);
			ldap_unbind_ext(*ld, NULL, NULL);
			*ld = NULL;
			return lderr;
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

		lderr = ldap_sasl_bind_s(*ld, u, q, &passwd,
		                         NULL, NULL, NULL);
		if (lderr != LDAP_SUCCESS)
		{
			if (err != NULL)
				*err = ldap_err2string(lderr);
			ldap_unbind_ext(*ld, NULL, NULL);
			*ld = NULL;
			return lderr;
		}
	}
	else
	{
# ifdef USE_SASL
		lderr = ldap_sasl_interactive_bind_s(*ld,
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
			ldap_unbind_ext(*ld, NULL, NULL);
			*ld = NULL;
			return lderr;
		}

# else /* USE_SASL */

		/* unknown auth mechanism */
		if (err != NULL)
			*err = "Unknown auth mechanism";
		ldap_unbind_ext(*ld, NULL, NULL);
		*ld = NULL;
		return LDAP_AUTH_METHOD_NOT_SUPPORTED;

# endif /* USE_SASL */
	}

	return LDAP_SUCCESS;
}
#endif /* USE_LDAP */

#ifdef USE_ODBX
/*
**  DKIMF_DB_OPEN_SQL -- attempt to contact an SQL server
**
**  Parameters:
**  	dsn -- connection description
**  	odbx -- ODBX handle (updated on success)
**  	err -- pointer to error string (updated on failure)
**
**  Return value:
**  	Status from odbx_init().
*/

int
dkimf_db_open_sql(struct dkimf_db_dsn *dsn, odbx_t **odbx, char **err)
{
	int dberr;

	assert(dsn != NULL);
	assert(odbx != NULL);

	/* create odbx handle */
	dberr = odbx_init(odbx,
	                  STRORNULL(dsn->dsn_backend),
	                  STRORNULL(dsn->dsn_host),
	                  STRORNULL(dsn->dsn_port));

	if (dberr < 0)
	{
		if (err != NULL)
			*err = (char *) odbx_error(NULL, dberr);
		return dberr;
	}

	/* create bindings */
	dberr = odbx_bind(*odbx, STRORNULL(dsn->dsn_dbase),
	                         STRORNULL(dsn->dsn_user),
	                         STRORNULL(dsn->dsn_password),
	                         ODBX_BIND_SIMPLE);
	if (dberr < 0)
	{
		if (err != NULL)
			*err = (char *) odbx_error(*odbx, dberr);
		(void) odbx_finish(*odbx);
		return dberr;
	}

	return 0;
}
#endif /* USE_ODBX */

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

#ifdef USE_ERLANG
/*
**  DKIMF_DB_ERL_CONNECT -- connect to a distributed Erlang node
**
**  Parameters:
**	db -- DKIMF_DB handle
**	ecp -- Pointer to ei_cnode
**
**  Return value:
**	File descriptor or -1 on error.
*/

static int
dkimf_db_erl_connect(DKIMF_DB db, ei_cnode *ecp)
{
	int fd;
	int ret;
	int instance;
	unsigned int seed;
	char node_name[12];
	struct timeval tv;
	char *q;
	char *last;
	struct dkimf_db_erlang *e;

	gettimeofday(&tv, NULL);
	seed = tv.tv_sec * tv.tv_usec;
	instance = rand_r(&seed) % 999;

	e = (struct dkimf_db_erlang *) db->db_data;

	snprintf(node_name, sizeof node_name, "opendkim%d", instance);

	ret = ei_connect_init(ecp, node_name, e->erlang_cookie, instance);
	if (ret != 0)
		return -1;

	fd = -1;
	for (q = strtok_r(e->erlang_nodes, ",", &last);
	     q != NULL;
	     q = strtok_r(NULL, ",", &last))
	{
		fd = ei_connect(ecp, q);
		if (fd >= 0)
			break;
	}
	if (fd < 0)
		return -1;

	return fd;
}

/*
**  DKIMF_DB_ERL_FREE -- free allocated memory for Erlang configuration
**
**  Parameters:
**	ep -- Pointer to struct dkimf_db_erlang
**
**  Return value:
**	None.
*/

static void
dkimf_db_erl_free(struct dkimf_db_erlang *ep)
{
	if (ep == NULL)
		return;
	if (ep->erlang_nodes != NULL)
		free(ep->erlang_nodes);
	if (ep->erlang_module != NULL)
		free(ep->erlang_module);
	if (ep->erlang_function != NULL)
		free(ep->erlang_function);
	if (ep->erlang_cookie != NULL)
		free(ep->erlang_cookie);
	free(ep);
}

/*
**  DKIMF_DB_ERL_ALLOC_BUFFER -- allocate memory for a char* buffer
**                               depending on erlang response size
**
**  Parameters:
**	eip -- pointer to response ei_x_buff
**	index -- pointer to current response index
**	sizep -- size of response (returned)
**
** Return value:
**	Pointer to allocated buffer or NULL on error.
*/

static char *
dkimf_db_erl_alloc_buffer(ei_x_buff *eip, int *index, int *sizep)
{
	int err;
	int type, size;

	err = ei_get_type(eip->buff, index, &type, &size);
	if (err < 0)
		return NULL;
	*sizep = size + 1;
	return malloc(*sizep);
}

/*
**  DKIMF_DB_ERL_DECODE_ATOM -- decode an Erlang atom and check it
**                              against its desired value
**
**  Parameters:
**	eip -- pointer to response ei_x_buff
**	index -- pointer to current response index
**	cmp -- desired atom value
**
**  Return value:
**	0 if the atom value matches de desired value, != 0 otherwise.
*/

static int
dkimf_db_erl_decode_atom(ei_x_buff *eip, int *index, const char *cmp)
{
	int err;
	int size;
	int ret;
	char *buf;

	buf = dkimf_db_erl_alloc_buffer(eip, index, &size);
	err = ei_decode_atom(eip->buff, index, buf);
	if (err != 0)
		return err;
	buf[size - 1] = '\0';

	ret = strcmp(buf, cmp);

	free(buf);
	return ret;
}

/*
**  DKIMF_DB_ERL_DECODE_TUPLE -- decode an Erlang tuple, optionally
**                               checking its arity
**
**  Parameters:
**	eip -- pointer to response ei_x_buff
**	index -- pointer to current response index
**	num_elements -- pointer desired tuple arity (returned)
**
**  Return value:
**	0 -- success
**	-1 -- error.
**
**  Notes:
**	If num_elements points to a positive number, the decoded tuple
**	arity is checked against it, and if the values differ, the function
**      will return an error.  Otherwise, num_elements is set to the decoded
**      tuple arity.
*/

static int
dkimf_db_erl_decode_tuple(ei_x_buff *eip, int *index, int *num_elements)
{
	int err;
	int arity;

	err = ei_decode_tuple_header(eip->buff, index, &arity);
	if (err < 0)
		return err;
	if (*num_elements > 0 && *num_elements != arity)
		return -1;
	*num_elements = arity;
	return 0;
}

/*
**  DKIMF_DB_ERL_DECODE_BITSTRING -- decode an Erlang bitstring
**
**  Parameters:
**	eip -- pointer to response ei_x_buff
**	index -- pointer to current response index
**
**  Return value:
**	Pointer to allocated buffer used to store the bitstring value
**      or NULL on error.
**
**  Notes:
**	The caller is responsible for freeing the buffer.
*/

static char *
dkimf_db_erl_decode_bitstring(ei_x_buff *eip, int *index)
{
	int err;
	int size;
	long len;
	char *buf;

	buf = dkimf_db_erl_alloc_buffer(eip, index, &size);
	err = ei_decode_binary(eip->buff, index, buf, &len);
	if (err < 0)
		return NULL;
	buf[size - 1] = '\0';
	return buf;
}

/*
**  DKIMF_DB_ERL_DECODE_INTEGER -- decode an Erlang integer
**
**  Parameters:
**	eip -- pointer to response ei_x_buff
**	index -- pointer to current response index
**      val -- pointer to decoded integer (returned)
**
**  Return value:
**	0: success
**      < 0: error
*/

static int
dkimf_db_erl_decode_int(ei_x_buff *eip, int *index, long *val)
{
	int err;

	err = ei_decode_long(eip->buff, index, val);
	if (err < 0)
		return err;
	return 0;
}

/*
**  DKIMF_DB_ERL_DECODE_RESPONSE -- decode an Erlang RPC response
**
**  Parameters:
**	resp -- pointer to response ei_x_buff
**      notfound -- string containing the atom to be returned in case
**                  of a record not found
**	req -- list of data requests
**	reqnum -- number of data requests
**  	key -- buffer to receive the key (may be NULL)
**  	keylen -- bytes available at "key" (updated)
**
**  Return value:
**	-1: error
**      1: record not found
**	0: success
**
**  Notes:
**	Assumes keys returned from Erlang are either integers or
**      bitstrings.
*/

static int
dkimf_db_erl_decode_response(ei_x_buff *resp, const char *notfound,
                             DKIMF_DBDATA req, unsigned int reqnum,
                             char *key, size_t *keylen)
{
	int ret;
	int res_index, res_type, res_size;

	res_index = 0;
	ret = ei_get_type(resp->buff, &res_index, &res_type, &res_size);
	if (ret != 0)
		return -1;

	switch (res_type)
	{
	  case ERL_ATOM_EXT:
	  {
		/*
		**  If we got an atom then it must signal record not found or
		**  no more records in the table.
		*/

		ret = dkimf_db_erl_decode_atom(resp, &res_index, notfound);
		if (ret != 0)
			return -1;
		return 1;
	  }

	  case ERL_SMALL_TUPLE_EXT:
	  case ERL_LARGE_TUPLE_EXT:
	  {
		/* got a tuple {ok, something} */
		int nres;
		int arity;

		arity = 2;
		ret = dkimf_db_erl_decode_tuple(resp, &res_index, &arity);
		if (ret == -1)
			return -1;
		ret = dkimf_db_erl_decode_atom(resp, &res_index, "ok");
		if (ret != 0)
			return -1;

		ret = ei_get_type(resp->buff, &res_index, &res_type,
		                  &res_size);
		if (ret < 0)
			return -1;

		switch (res_type)
		{
		  case ERL_SMALL_INTEGER_EXT:
		  case ERL_INTEGER_EXT:
		  {
			/*
			**  The tuple is {ok, IntegerDomainId}
			**  (we were called from SigningTable)
			*/

			int c;
			int n;
			long val;

			if (reqnum == 0)
				return 0;
			ret = dkimf_db_erl_decode_int(resp, &res_index, &val);
			if (ret != 0)
				return -1;
			n = snprintf(req[0].dbdata_buffer,
			             req[0].dbdata_buflen, "%ld", val);
			req[0].dbdata_buflen = n + 1;
			for (c = 1; c < reqnum; c++)
				req[c].dbdata_buflen = 0;
			return 0;
		  }

		  case ERL_BINARY_EXT:
		  {
			/*
			**  The tuple is {ok, BitstringDomainId}
			**  (we were called from SigningTable)
			*/

			int c;
			char *val;

			if (reqnum == 0)
				return 0;
			val = dkimf_db_erl_decode_bitstring(resp, &res_index);
			if (val == NULL)
				return -1;
			req[0].dbdata_buflen = strlcpy(req[0].dbdata_buffer,
			                               val,
			                               req[0].dbdata_buflen);
			free(val);
			for (c = 1; c < reqnum; c++)
				req[c].dbdata_buflen = 0;
			return 0;
		  }

		  case ERL_SMALL_TUPLE_EXT:
		  case ERL_LARGE_TUPLE_EXT:
		  {
			/*
			**  The tuple is either
			**   {ok, {Cursor, Domain, Selector, PrivKey}}
			**  (we were called from dkimf_db_walk()); or
			**   {ok, {Domain, Selector, PrivKey}
			**  (we were called from dkimf_db_get()).
			*/

			int c;
			arity = 0;

			ret = dkimf_db_erl_decode_tuple(resp, &res_index,
			                                &arity);
			if (ret == -1)
				return -1;

			if (key != NULL && keylen != NULL)
			{
				ret = ei_get_type(resp->buff, &res_index,
				                  &res_type, &res_size);
				if (ret != 0)
					return -1;

				switch (res_type)
				{
				  case ERL_SMALL_INTEGER_EXT:
				  case ERL_INTEGER_EXT:
				  {
					int n;
					long val;
					ret = dkimf_db_erl_decode_int(resp,
					                              &res_index,
					                              &val);
					if (ret != 0)
						return -1;
					n = snprintf(key, *keylen, "%ld", val);
					*keylen = n + 1;
					break;
				  }

				  case ERL_BINARY_EXT:
				  {
					char *val;
					val = dkimf_db_erl_decode_bitstring(resp,
					                                    &res_index);
					if (val == NULL)
						return -1;

					*keylen = strlcpy(key, val,
					                       *keylen);
					free(val);
					break;
				  }

				  default:
					return -1;
				}
			}

			if (reqnum == 0)
				return 0;

			ret = ei_get_type(resp->buff, &res_index, &res_type,
			                  &res_size);
			if (ret != 0)
				return -1;

			nres = (key != NULL && keylen != NULL) ? arity - 1
			                                       : arity;
			for (c = 0; c < reqnum; c++)
			{
				if (c >= nres)
				{
					req[c].dbdata_buflen = 0;
				}
				else
				{
					char *val;
					val = dkimf_db_erl_decode_bitstring(resp,
					                                    &res_index);
					if (val == NULL)
						return -1;
					req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
					                       val,
					                       req[c].dbdata_buflen);
					free(val);
				}
			}

			return 0;
		  }

		  default:
			  return -1;
		}
	  }

	  default:
		return -1;
	}
}
#endif /* USE_ERLANG */

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
**  	erlang -- an erlang function to be called in a distributed erlang node
*/

int
dkimf_db_open(DKIMF_DB *db, char *name, u_int flags, pthread_mutex_t *lock,
              char **err)
{
	DKIMF_DB new;
	char *comma;
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

	new->db_flags = (flags | gflags);
	new->db_type = DKIMF_DB_TYPE_UNKNOWN;

	p = strchr(name, ':');
	comma = strchr(name, ',');

	/* catch a CSL that contains colons not in the first entry */
	if (comma != NULL && p != NULL && comma < p)
		p = NULL;

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
	if (new->db_type == DKIMF_DB_TYPE_DSN ||
	    new->db_type == DKIMF_DB_TYPE_SOCKET)
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

		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) == 0)
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
						return -1;
					}
					dkimf_trimspaces(newl->db_list_key);

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
					dkimf_trimspaces(newl->db_list_value);

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
				dkimf_trimspaces(newl->db_list_key);

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
					dkimf_trimspaces(newl->db_list_value);
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

		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) == 0)
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

					newl->db_list_key = strdup(key);
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
					dkimf_trimspaces(newl->db_list_key);

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
					dkimf_trimspaces(newl->db_list_value);

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
				dkimf_trimspaces(newl->db_list_key);

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
					dkimf_trimspaces(newl->db_list_value);
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

		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) == 0)
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
				else if (end == NULL &&
				         isascii(*p) && isspace(*p))
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
				dkimf_trimspaces(newl->db_relist_data);
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
		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) != 0)
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

		if (*p == '\0')
		{
			new->db_flags |= DKIMF_DB_FLAG_NOFDLOCK;
			flags = new->db_flags;
			p = NULL;
		}

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
		               (new->db_flags & DKIMF_DB_FLAG_READONLY ? O_RDONLY
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
		**  key-value pairs.  "filter" is optional.
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
			else if (strcasecmp(p, "filter") == 0)
			{
				size_t len;

				len = strlen(eq + 1) + 1;

				dsn->dsn_filter = malloc(len);
				if (dsn->dsn_filter != NULL)
				{
					int c;
					char *q;
					char *r;

					memset((void *) dsn->dsn_filter,
					       '\0', len);

					r = (char *) dsn->dsn_filter;

					for (q = eq + 1;
					     q < eq + len;
					     q++)
					{
						if (*q == '=' &&
						    isxdigit(*(q + 1)) &&
						    isxdigit(*(q + 2)))
						{
							c = 16 * dkimf_db_hexdigit(*(q + 1));
							c += dkimf_db_hexdigit(*(q + 2));
							*r++ = c;
							q += 2;
						}
						else
						{
							*r++ = *q;
						}
					}
				}
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
			free(new);
			return -1;
		}

# ifdef _FFR_DB_HANDLE_POOLS
		new->db_handle = dkimf_db_hp_new(new->db_type,
		                                 DEFPOOLMAX, dsn);
		if (new == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(dsn);
			free(tmp);
			free(new);
			return -1;
		}
# else /* _FFR_DB_HANDLE_POOLS */
		/* create odbx handle */
		if (dkimf_db_open_sql(dsn, &odbx, err) < 0)
		{
			if ((new->db_flags & DKIMF_DB_FLAG_SOFTSTART) == 0)
			{
				free(dsn);
				free(tmp);
				free(new);
				return -1;
			}
	
			new->db_iflags |= DKIMF_DB_IFLAG_RECONNECT;
			odbx = NULL;
		}

		/* store handle */
		new->db_handle = (void *) odbx;
# endif /* _FFR_DB_HANDLE_POOLS */

		new->db_data = (void *) dsn;

		/* clean up */
		free(tmp);

		break;
	  }
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		int c;
		int lderr;
		size_t rem;
		size_t plen;
		struct dkimf_db_ldap *ldap;
		LDAP *ld;
		char *q;
		char *r;
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
		q = dkimf_db_ldap_param[DKIMF_LDAP_PARAM_TIMEOUT];
		if (q == NULL)
		{
			ldap->ldap_timeout = DKIMF_LDAP_DEFTIMEOUT;
		}
		else
		{
			errno = 0;
			ldap->ldap_timeout = strtoul(q, &r, 10);
			if (errno == ERANGE)
				ldap->ldap_timeout = DKIMF_LDAP_DEFTIMEOUT;
		}

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

			q += plen;
			rem -= plen;

			ldap_free_urldesc(descr);
		}

		lderr = dkimf_db_open_ldap(&ld, ldap, err);
		if (lderr != LDAP_SUCCESS)
		{
			if ((new->db_flags & DKIMF_DB_FLAG_SOFTSTART) == 0)
			{
				if (err != NULL)
					*err = ldap_err2string(lderr);
				free(ldap);
				free(p);
				free(new);
				return -1;
			}
			else
			{
				ld = NULL;
			}
		}

		pthread_mutex_init(&ldap->ldap_lock, NULL);

# ifdef _FFR_LDAP_CACHING
#  ifdef USE_DB
		if ((new->db_flags & DKIMF_DB_FLAG_NOCACHE) == 0)
		{
			/* establish LDAP cache DB */
			lderr = 0;

#   if DB_VERSION_CHECK(3,0,0)
			lderr = db_create(&newdb, NULL, 0);
			if (lderr == 0)
			{
#    if DB_VERSION_CHECK(4,1,25)
	 			lderr = newdb->open(newdb, NULL, NULL, NULL,
				                    DB_HASH, DB_CREATE, 0);
#    else /* DB_VERSION_CHECK(4,1,25) */
				lderr = newdb->open(newdb, NULL, NULL, DB_HASH,
				                    DB_CREATE, 0);
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
		char *tmp;
		struct stat s;
		struct dkimf_lua_script_result lres;
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

		tmp = (void *) malloc(s.st_size + 1);
		if (tmp == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new->db_data);
			close(fd);
			return -1;
		}
		memset(tmp, '\0', s.st_size + 1);

		rlen = read(fd, tmp, s.st_size);
		if (rlen < s.st_size)
		{
			if (err != NULL)
			{
				if (rlen == -1)
					*err = strerror(errno);
				else
					*err = "Read truncated";
			}
			free(tmp);
			free(new->db_data);
			close(fd);
			return -1;
		}

		close(fd);

		/* try to compile it */
		if (dkimf_lua_db_hook(tmp, 0, NULL, &lres, 
		                      (void *) &lua->lua_script,
		                      &lua->lua_scriptlen) != 0)
		{
			if (err != NULL)
				*err = "Lua compilation error";
			free(tmp);
			free(new->db_data);
			return -1;
		}

		free(tmp);
		break;
	  }
#endif /* USE_LUA */

#ifdef USE_LIBMEMCACHED
	  case DKIMF_DB_TYPE_MEMCACHE:
	  {
		in_port_t port;
		char *colon;
		char *q;
		char *key;
		char *last;
		char *tmp;
		memcached_st *mcs = NULL;

		tmp = strdup(p);
		if (tmp == NULL)
			return -1;

		q = strchr(tmp, '/');
		if (q == NULL)
		{
			free(tmp);
			return -1;
		}
		*q = '\0';

		key = strdup(q + 1);
		if (key == NULL)
		{
			free(tmp);
			return -1;
		}

		mcs = memcached_create(NULL);
		if (mcs == NULL)
		{
			free(tmp);
			free(key);
			return -1;
		}

		for (q = strtok_r(tmp, ",", &last);
		     q != NULL;
		     q = strtok_r(NULL, ",", &last))
		{
			colon = strchr(q, ':');
			if (colon != NULL)
				*colon = '\0';

			if (colon == NULL)
				port = MEMCACHED_DEFAULT_PORT;
			else
				port = atoi(colon + 1);

			if (memcached_server_add(mcs,
			                         q, port) != MEMCACHED_SUCCESS)
			{
				free(tmp);
				free(key);
				memcached_free(mcs);
				return -1;
			}
		}

		new->db_handle = mcs;
		new->db_data = key;

		free(tmp);
		break;
	  }
#endif /* USE_LIBMEMCACHED */

#ifdef _FFR_REPUTATION
	  case DKIMF_DB_TYPE_REPUTE:
	  {
		unsigned int reporter = 0;
		char *q;
		REPUTE r;
		char useragent[BUFRSZ + 1];

		q = strchr(p, ':');
		if (q != NULL)
		{
			char *s;

			*q = '\0';
			reporter = (unsigned int) strtoul(q + 1, &s, 10);
			if (*s != '\0')
			 	return -1;
		}

		r = repute_new(p, reporter);
		if (r == NULL)
			return -1;

		q = (char *) repute_curlversion(r);
		snprintf(useragent, sizeof useragent, "%s/%s %s%s%s",
		         DKIMF_PRODUCTNS, VERSION,
		         "libcurl",
		         q == NULL ? "" : "/",
		         q == NULL ? "" : q);
		repute_useragent(r, useragent);

		new->db_data = (void *) r;

		break;
	  }
#endif /* _FFR_REPUTATION */

#ifdef _FFR_SOCKETDB
	  case DKIMF_DB_TYPE_SOCKET:
	  {
		int fd;
		int status;
		struct dkimf_db_socket *sdb;

		sdb = (struct dkimf_db_socket *) malloc(sizeof *sdb);
		if (sdb == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return 2;
		}

		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(new);
			errno = EINVAL;
			return 2;
		}

		if (*p == '/')
		{					/* UNIX domain */
			struct sockaddr_un sun;

			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0)
			{
				if (err != NULL)
					*err = strerror(errno);
				free(new);
				return 2;
			}

			memset(&sun, '\0', sizeof sun);
			sun.sun_family = AF_UNIX;
#ifdef HAVE_SUN_LEN
			sun.sun_len = sizeof(sun);
#endif /* HAVE_SUN_LEN */
			strlcpy(sun.sun_path, p, sizeof(sun.sun_path));

			status = connect(fd, (struct sockaddr *) &sun,
			                 sizeof sun);
			if (status < 0)
			{
				if (err != NULL)
					*err = strerror(errno);
				free(new);
				return 2;
			}
		}
		else
		{					/* port@host */
			int af;
			char *at;
			char *q;
			uint16_t port;
			struct in_addr ip4;
# ifdef AF_INET6
			struct in6_addr ip6;
# endif /* AF_INET6 */

			at = strchr(p, '@');
			if (at == NULL)
			{
				if (err != NULL)
					*err = strerror(EINVAL);
				free(new);
				errno = EINVAL;
				return 2;
			}

			*at = '\0';

			port = (uint16_t) strtoul(p, &q, 10);
			if (*q != '\0')
			{
				struct servent *srv;

				srv = getservbyname(p, "tcp");
				if (srv == NULL)
				{
					if (err != NULL)
						*err = strerror(EINVAL);
					free(new);
					errno = EINVAL;
					return 2;
				}

				port = srv->s_port;
			}
			else
			{
				port = htons(port);
			}

			fd = -1;

			if (inet_pton(AF_INET, at + 1, &ip4) == 1)
			{
				af = AF_INET;
			}
# ifdef AF_INET6
			else if (inet_pton(AF_INET6, at + 1, &ip6) == 1)
			{
				af = AF_INET6;
			}
# endif /* AF_INET6 */
			else
			{
# ifdef HAVE_GETADDRINFO
				int save_errno;
				struct addrinfo hint;
				struct addrinfo *aitop;
				struct addrinfo *aicur;
				struct protoent *proto;

				proto = getprotobyname("tcp");
				if (proto == NULL)
				{
					if (err != NULL)
						*err = strerror(EPROTONOSUPPORT);
					free(new);
					errno = EPROTONOSUPPORT;
					return 2;
				}

				memset(&hint, '\0', sizeof hint);
				hint.ai_protocol = proto->p_proto;

				status = getaddrinfo(at + 1, p, &hint, &aitop);
				if (status != 0)
				{
					if (err != NULL)
						*err = (char *) gai_strerror(status);
					free(new);
					errno = EINVAL;
					return 2;
				}

				for (aicur = aitop;
				     aicur != NULL;
				     aicur = aicur->ai_next)
				{
					fd = socket(aicur->ai_family,
					            aicur->ai_socktype,
					            aicur->ai_protocol);
					if (fd == -1)
					{
						save_errno = errno;
						continue;
					}

					status = connect(fd, aicur->ai_addr,
					                 aicur->ai_addrlen);
					if (status == 0)
						break;

					save_errno = errno;
					close(fd);
					fd = -1;
				}

				freeaddrinfo(aitop);

				if (fd == -1)
				{
					if (err != NULL)
						*err = strerror(save_errno);
					free(new);
					errno = save_errno;
					return 2;
				}
# else /* HAVE_GETADDRINFO */
				struct hostent *h;
				struct sockaddr_in sin4;
#  ifdef HAVE_GETHOSTBYNAME2
				struct sockaddr_in6 sin6;

				h = gethostbyname2(at + 1, AF_INET6);
				if (h != NULL)
				{
					af = AF_INET6;

					fd = socket(AF_INET6, SOCK_STREAM, 0);
					if (fd < 0)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(new);
						return 2;
					}

					for (c = 0;
					     h->h_addr_list[c] != NULL;
					     c++)
					{
						memset(&sin6, '\0',
						       sizeof sin6);

						sin6.sin6_family = AF_INET6;
						sin6.sin6_port = port;
						memcpy(&sin6.sin6_addr,
						       h->h_addr_list[c],
						       sizeof sin6.sin6_addr);

						status = connect(fd,
						                 (struct sockaddr *) &sin6,
						                 sizeof sin6);
						if (status == 0)
							break;

						save_errno = errno;
					}

					close(fd);
					fd = -1;
				}
#  endif /* HAVE_GETHOSTBYNAME2 */

				h = gethostbyname(at + 1);
				if (h != NULL)
				{
					af = AF_INET;

					fd = socket(AF_INET, SOCK_STREAM, 0);
					if (fd < 0)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(new);
						return 2;
					}

					for (c = 0;
					     h->h_addr_list[c] != NULL;
					     c++)
					{
						memset(&sin4, '\0',
						       sizeof sin4);

						sin.sin_family = AF_INET;
						sin.sin_port = port;
						memcpy(&sin.sin_addr,
						       h->h_addr_list[c],
						       sizeof sin.sin_addr);

						status = connect(fd,
						                 (struct sockaddr *) &sin4,
						                 sizeof sin4);
						if (status == 0)
							break;

						save_errno = errno;
					}

					close(fd);
					fd = -1;
				}

				if (fd == -1)
				{
					if (err != NULL)
						*err = strerror(save_errno);
					free(new);
					errno = save_errno;
					return 2;
				}
# endif /* HAVE_GETADDRINFO */
			}

			if (fd == -1)
			{
				int save_errno;

				fd = socket(af, SOCK_STREAM, 0);
				if (fd < 0)
				{
					if (err != NULL)
						*err = strerror(errno);
					free(new);
					return 2;
				}

# ifdef AF_INET6
				if (af == AF_INET6)
				{
					struct sockaddr_in6 sin6;

					memset(&sin6, '\0', sizeof sin6);

					sin6.sin6_family = AF_INET6;
					sin6.sin6_port = port;
					memcpy(&sin6.sin6_addr, &ip6,
					       sizeof sin6.sin6_addr);

					status = connect(fd,
					                 (struct sockaddr *) &sin6,
					                 sizeof sin6);

					if (status != 0)
					{
						save_errno = errno;
						close(fd);
						if (err != NULL)
							*err = strerror(save_errno);
						free(new);
						return 2;
					}
				}
# endif /* AF_INET6 */

				if (af == AF_INET)
				{
					struct sockaddr_in sin4;

					memset(&sin4, '\0', sizeof sin4);

					sin4.sin_family = AF_INET;
					sin4.sin_port = port;
					memcpy(&sin4.sin_addr, &ip4,
					       sizeof sin4.sin_addr);

					status = connect(fd,
					                 (struct sockaddr *) &sin4,
					                 sizeof sin4);

					if (status != 0)
					{
						save_errno = errno;
						close(fd);
						if (err != NULL)
							*err = strerror(save_errno);
						free(new);
						return 2;
					}
				}
			}
		}

		sdb->sockdb_fd = fd;
		sdb->sockdb_buf = dkimf_dstring_new(BUFRSZ, 0);

		new->db_handle = sdb;

		break;
	  }
#endif /* _FFR_SOCKETDB */

#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		int status;
		struct dkimf_db_mdb *mdb;

		mdb = (struct dkimf_db_mdb *) malloc(sizeof *mdb);
		if (mdb == NULL)
			return -1;

		status = mdb_env_create(&mdb->mdb_env);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			free(mdb);
			return -1;
		}

		status = mdb_env_open(mdb->mdb_env, p, 0, 0);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			mdb_env_close(mdb->mdb_env);
			free(mdb);
			return -1;
		}

		status = mdb_txn_begin(mdb->mdb_env, NULL, 0, &mdb->mdb_txn);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			mdb_env_close(mdb->mdb_env);
			free(mdb);
			return -1;
		}

		status = mdb_dbi_open(mdb->mdb_txn, NULL, 0, &mdb->mdb_dbi);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			mdb_txn_abort(mdb->mdb_txn);
			mdb_env_close(mdb->mdb_env);
			free(mdb);
			return -1;
		}

		new->db_data = (void *) mdb;

		break;
	  }
#endif /* USE_MDB */

#ifdef USE_ERLANG
	  case DKIMF_DB_TYPE_ERLANG:
	  {
		_Bool err = FALSE;
		int c;
		char *q;
		char *last;
		char *r;
		char *tmp;
		struct dkimf_db_erlang *e;

		/*
		**  Erlang dataset configuration format:
		**   erlang:node1,node2,...:cookie:module:function
		*/

		tmp = strdup(p);
		if (tmp == NULL)
			return -1;

		e = calloc(1, sizeof *e);
		if (e == NULL)
		{
			free(tmp);
			return -1;
		}

		c = 0;

		for (q = strtok_r(tmp, ":", &last);
		     !err && q != NULL;
		     q = strtok_r(NULL, ":", &last))
		{
			switch (c)
			{
			  case 0:
				e->erlang_nodes = strdup(q);
				if (e->erlang_nodes == NULL)
					err = TRUE;
				break;

			  case 1:
				e->erlang_cookie = strdup(q);
				if (e->erlang_cookie == NULL)
					err = TRUE;
				break;

			  case 2:
				e->erlang_module = strdup(q);
				if (e->erlang_module == NULL)
					err = TRUE;
				break;

			  case 3:
				e->erlang_function = strdup(q);
				if (e->erlang_function == NULL)
					err = TRUE;
				break;

			  case 4:
				err = TRUE;
				break;
			}

			c++;
		}

		if (err || c < 3)
		{
			free(tmp);
			dkimf_db_erl_free(e);
			return -1;
		}

		new->db_data = e;
		free(tmp);
		break;
	  }
#endif /* USE_ERLANG */
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
	    db->db_type == DKIMF_DB_TYPE_MEMCACHE || 
	    db->db_type == DKIMF_DB_TYPE_REPUTE || 
	    db->db_type == DKIMF_DB_TYPE_REFILE ||
	    db->db_type == DKIMF_DB_TYPE_ERLANG)
		return EINVAL;

#ifdef USE_DB
	bdb = (DB *) db->db_handle;

	memset(&q, 0, sizeof q);
	q.data = (char *) buf;
	q.size = (buflen == 0 ? strlen(q.data) : buflen);

	ret = 0;

	/* establish write-lock */
	fd = -1;
	status = 0;
	if ((db->db_flags & DKIMF_DB_FLAG_NOFDLOCK) == 0)
	{
# if DB_VERSION_CHECK(2,0,0)
		status = bdb->fd(bdb, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
		fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */
	}

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
#ifdef USE_MDB
	MDB_val key;
	MDB_val data;
	MDB_dbi dbi;
	MDB_txn *txn;
	struct dkimf_db_mdb *mdb;
#endif /* USE_MDB */

	assert(db != NULL);
	assert(buf != NULL);
	assert(outbuf != NULL);

	if (db->db_type == DKIMF_DB_TYPE_FILE ||
	    db->db_type == DKIMF_DB_TYPE_CSL || 
	    db->db_type == DKIMF_DB_TYPE_DSN || 
	    db->db_type == DKIMF_DB_TYPE_LDAP || 
	    db->db_type == DKIMF_DB_TYPE_LUA || 
	    db->db_type == DKIMF_DB_TYPE_REPUTE || 
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
	status = 0;
	if ((db->db_flags & DKIMF_DB_FLAG_NOFDLOCK) == 0)
	{
# if DB_VERSION_CHECK(2,0,0)
		status = bdb->fd(bdb, &fd);
		if (status != 0)
		{
			db->db_status = status;
			return status;
		}
# else /* DB_VERSION_CHECK(2,0,0) */
		fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */
	}

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

#ifdef USE_MDB
	mdb = db->db_data;

	if (db->db_lock != NULL)
		(void) pthread_mutex_lock(db->db_lock);

	key.mv_data = outbuf;
	key.mv_size = outbuflen;
	data.mv_data = (char *) buf;
	data.mv_size = (buflen == 0 ? strlen(buf) : buflen);

	if (mdb_txn_begin(mdb->mdb_env, NULL, 0, &txn) == 0 &&
	    mdb_dbi_open(txn, NULL, 0, &dbi) == 0 &&
	    mdb_put(txn, dbi, &key, &data, 0) == 0)
		ret = 0;
	else
		ret = -1;

	if (txn != NULL)
	{
		if (ret == 0)
			mdb_txn_commit(txn);
		else
			mdb_txn_abort(txn);
	}

	if (db->db_lock != NULL)
		(void) pthread_mutex_unlock(db->db_lock);
#endif /* USE_MDB */

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

	/*
	**  Indicate "not found" if we require ASCII-only and there was
	**  non-ASCII in the query.
	*/

	if ((db->db_flags & DKIMF_DB_FLAG_ASCIIONLY) != 0)
	{
		char *p;
		char *end;

		end = (char *) buf + buflen;

		for (p = (char *) buf; p <= end; p++)
		{
			if (!isascii(*p))
			{
				if (*exists)
					*exists = FALSE;

				return 0;
			}
		}
	}

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
		status = 0;
		if ((db->db_flags & DKIMF_DB_FLAG_NOFDLOCK) == 0)
		{
# if DB_VERSION_CHECK(2,0,0)
			status = bdb->fd(bdb, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
			fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */
		}

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
		_Bool reconnected = FALSE;
		int err;
		int fields;
		int rescnt = 0;
		int rowcnt = 0;
		u_long elen;
		odbx_result_t *result;
		odbx_t *odbx = NULL;
		struct dkimf_db_dsn *dsn;
		char query[BUFRSZ];
		char escaped[BUFRSZ];

		dsn = (struct dkimf_db_dsn *) db->db_data;

# ifdef _FFR_DB_HANDLE_POOLS
		odbx = dkimf_db_hp_get((struct handle_pool *) db->db_handle,
		                       &err);
		if (odbx == NULL)
		{
			db->db_status = err;
			return -1;
		}
# else /* _FFR_DB_HANDLE_POOLS */
		if (db->db_lock != NULL)
			(void) pthread_mutex_lock(db->db_lock);

		/* see if we need to reopen */
		if ((db->db_iflags & DKIMF_DB_IFLAG_RECONNECT) != 0)
		{
			err = dkimf_db_open_sql(dsn, (odbx_t **) &db->db_handle,
			                        NULL);
			if (err < 0)
			{
				db->db_status = err;
				return -1;
			}

			reconnected = TRUE;
			db->db_iflags &= ~DKIMF_DB_IFLAG_RECONNECT;
		}

		odbx = (odbx_t *) db->db_handle;

# endif /* _FFR_DB_HANDLE_POOLS */

		memset(escaped, '\0', sizeof escaped);
		elen = sizeof escaped - 1;
		err = odbx_escape(odbx, buf,
		                  (buflen == 0 ? strlen(buf) : buflen),
		                  escaped, &elen);
		if (err < 0)
		{
			db->db_status = err;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);

# ifdef _FFR_DB_HANDLE_POOLS
			dkimf_db_hp_put((struct handle_pool *) db->db_handle,
			                (void *) odbx);
# endif /* _FFR_DB_HANDLE_POOLS */

			return err;
		}

		snprintf(query, sizeof query,
		         "SELECT %s FROM %s WHERE %s = '%s'%s%s",
		         dsn->dsn_datacol,
		         dsn->dsn_table,
		         dsn->dsn_keycol, escaped,
		         dsn->dsn_filter == NULL ? "" : " AND ",
		         dsn->dsn_filter == NULL ? "" : dsn->dsn_filter);

		err = odbx_query(odbx, query, 0);
		if (err < 0)
		{
			int status;

			db->db_status = err;

			if (reconnected)
			{
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
# ifdef _FFR_DB_HANDLE_POOLS
				dkimf_db_hp_put((struct handle_pool *) db->db_handle,
				                (void *) odbx);
# endif /* _FFR_DB_HANDLE_POOLS */

				return err;
			}

			status = odbx_error_type(odbx, err);

#ifdef _FFR_POSTGRESQL_RECONNECT_HACK
			if (status >= 0)
			{
				const char *estr;

				estr = odbx_error(odbx, db->db_status);

				if (estr != NULL &&
				    strncmp(estr, "FATAL:", 6) == 0)
					status = -1;
			}
#endif /* _FFR_POSTGRESQL_RECONNECT_HACK */

			if (status < 0)
			{
				(void) odbx_unbind(odbx);
				(void) odbx_finish(odbx);

# ifdef _FFR_DB_HANDLE_POOLS
				dkimf_db_hp_dead((struct handle_pool *) db->db_handle);
# else /* _FFR_DB_HANDLE_POOLS */
				db->db_iflags |= DKIMF_DB_IFLAG_RECONNECT;
# endif /* _FFR_DB_HANDLE_POOLS */

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
			err = odbx_result(odbx, &result, NULL, 0);
			if (err < 0)
			{
				int status;
				db->db_status = err;

				if (reconnected)
				{
					if (db->db_lock != NULL)
						(void) pthread_mutex_unlock(db->db_lock);
# ifdef _FFR_DB_HANDLE_POOLS
					dkimf_db_hp_put((struct handle_pool *) db->db_handle,
					                (void *) odbx);
# endif /* _FFR_DB_HANDLE_POOLS */
					return err;
				}

				status = odbx_error_type(odbx, err);

#ifdef _FFR_POSTGRESQL_RECONNECT_HACK
				if (status >= 0)
				{
					const char *estr;

					estr = odbx_error(odbx, db->db_status);

					if (estr != NULL &&
					    strncmp(estr, "FATAL:", 6) == 0)
						status = -1;
				}
#endif /* _FFR_POSTGRESQL_RECONNECT_HACK */

				if (result != NULL)
					(void) odbx_result_finish(result);

				if (status < 0)
				{
					(void) odbx_unbind(odbx);
					(void) odbx_finish(odbx);

# ifdef _FFR_DB_HANDLE_POOLS
					dkimf_db_hp_dead((struct handle_pool *) db->db_handle);
# else /* _FFR_DB_HANDLE_POOLS */
					db->db_iflags |= DKIMF_DB_IFLAG_RECONNECT;
# endif /* _FFR_DB_HANDLE_POOLS */

					if (db->db_lock != NULL)
						(void) pthread_mutex_unlock(db->db_lock);

					return dkimf_db_get(db, buf, buflen,
					                    req, reqnum,
					                    exists);
				}

				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
# ifdef _FFR_DB_HANDLE_POOLS
				dkimf_db_hp_put((struct handle_pool *) db->db_handle,
				                (void *) odbx);
# endif /* _FFR_DB_HANDLE_POOLS */

				return err;
			}
			else if (err == ODBX_RES_DONE)
			{
				if (exists != NULL && rescnt == 0)
					*exists = FALSE;
				err = odbx_result_finish(result);
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
# ifdef _FFR_DB_HANDLE_POOLS
				dkimf_db_hp_put((struct handle_pool *) db->db_handle,
				                (void *) odbx);
# endif /* _FFR_DB_HANDLE_POOLS */

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
# ifdef _FFR_DB_HANDLE_POOLS
					dkimf_db_hp_put((struct handle_pool *) db->db_handle,
					                (void *) odbx);
# endif /* _FFR_DB_HANDLE_POOLS */
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

# ifdef _FFR_DB_HANDLE_POOLS
		dkimf_db_hp_put((struct handle_pool *) db->db_handle,
		                (void *) odbx);
# endif /* _FFR_DB_HANDLE_POOLS */

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

		if (ld == NULL)
		{
			int lderr;

			lderr = dkimf_db_open_ldap(&ld, ldap, NULL);
			if (lderr == LDAP_SUCCESS)
			{
				db->db_handle = ld;
			}
			else
			{
				db->db_status = lderr;
				pthread_mutex_unlock(&ldap->ldap_lock);
				return lderr;
			}
		}

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

		dkimf_db_mkldapquery(ldap->ldap_descr->lud_dn, buf, FALSE,
		                     query, sizeof query);
		if (ldap->ldap_descr->lud_filter != NULL)
		{
			dkimf_db_mkldapquery(ldap->ldap_descr->lud_filter, buf,
			                     FALSE, filter, sizeof filter);
		}

		timeout.tv_sec = ldap->ldap_timeout;
		timeout.tv_usec = 0;

		status = ldap_search_ext_s(ld, query,
		                           ldap->ldap_descr->lud_scope,
		                           filter,
		                           ldap->ldap_descr->lud_attrs,
		                           0, NULL, NULL,
		                           &timeout, 0, &result);
		if (LDAP_NAME_ERROR(status))
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
		else if (status == LDAP_SERVER_DOWN ||
		         status == LDAP_TIMEOUT)
		{
			ldap_unbind_ext(ld, NULL, NULL);
			db->db_handle = NULL;
			if ((db->db_iflags & DKIMF_DB_IFLAG_RECONNECT) != 0)
			{
				db->db_status = status;
				pthread_mutex_unlock(&ldap->ldap_lock);
				return -1;
			}

			db->db_iflags |= DKIMF_DB_IFLAG_RECONNECT;

			pthread_mutex_unlock(&ldap->ldap_lock);

			status = dkimf_db_get(db, buf, buflen, req, reqnum,
			                      exists);

			db->db_iflags &= ~DKIMF_DB_IFLAG_RECONNECT;

			return status;
		}
		else if (status != LDAP_SUCCESS)
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
			ldap_msgfree(result);
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

		status = dkimf_lua_db_hook((const char *) lua->lua_script,
		                           lua->lua_scriptlen,
		                           (const char *) buf, &lres,
		                           NULL, NULL);
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

#ifdef USE_LIBMEMCACHED
	  case DKIMF_DB_TYPE_MEMCACHE:
	  {
		memcached_st *mcs;
		memcached_return_t ret;
		char *out;
		char *key;
		size_t vlen;
		uint32_t flags;
		char query[BUFRSZ + 1];

		mcs = (memcached_st *) db->db_handle;
		key = (char *) db->db_data;

		snprintf(query, sizeof query, "%s:%s", key, (char *) buf);
		
		out = memcached_get(mcs, query, strlen(query), &vlen,
		                    &flags, &ret);

		if (out != NULL)
		{
			if (exists != NULL)
				*exists = TRUE;

			if (dkimf_db_datasplit(out, vlen, req, reqnum) != 0)
			{
				free(out);
				return -1;
			}

			free(out);
			return 0;
		}
		else if (ret == MEMCACHED_NOTFOUND)
		{
			if (exists != NULL)
				*exists = FALSE;

			return 0;
		}
		else
		{
			db->db_status = (int) ret;
			return -1;
		}
	  }
#endif /* USE_LIBMEMCACHED */

#ifdef _FFR_REPUTATION
	  case DKIMF_DB_TYPE_REPUTE:
	  {
		_Bool found = FALSE;
		int c;
		float rep;
		float conf;
		unsigned long samp;
		unsigned long limit;
		time_t when;
		REPUTE_STAT rstat;
		REPUTE r;

		r = (REPUTE) db->db_data;

		if (!found)
		{
			rstat = repute_query(r, (char *) buf, &rep, &conf,
			                     &samp, &limit, &when);

			if (rstat == REPUTE_STAT_PARSE)
				return 0;
			else if (rstat != REPUTE_STAT_OK)
				return -1;

			if (exists != NULL)
				*exists = TRUE;
		}

		if (reqnum >= 1 && req[0].dbdata_buffer != NULL &&
		    req[0].dbdata_buflen != 0)
		{
			if ((req[0].dbdata_flags & DKIMF_DB_DATA_BINARY) != 0)
			{
				if (req[0].dbdata_buflen != sizeof rep)
					return -1;
				memcpy(req[0].dbdata_buffer, &rep, sizeof rep);
			}
			else
			{
				req[0].dbdata_buflen = snprintf(req[0].dbdata_buffer,
				                                req[0].dbdata_buflen,
				                                "%f", rep);
			}
		}

		if (reqnum >= 2 && req[1].dbdata_buffer != NULL &&
		    req[1].dbdata_buflen != 0)
		{
			if ((req[1].dbdata_flags & DKIMF_DB_DATA_BINARY) != 0)
			{
				if (req[1].dbdata_buflen != sizeof conf)
					return -1;
				memcpy(req[1].dbdata_buffer, &conf,
				       sizeof conf);
			}
			else
			{
				req[1].dbdata_buflen = snprintf(req[1].dbdata_buffer,
				                                req[1].dbdata_buflen,
				                                "%f", conf);
			}
		}

		if (reqnum >= 3 && req[2].dbdata_buffer != NULL &&
		    req[2].dbdata_buflen != 0)
		{
			if ((req[2].dbdata_flags & DKIMF_DB_DATA_BINARY) != 0)
			{
				if (req[2].dbdata_buflen != sizeof samp)
					return -1;
				memcpy(req[2].dbdata_buffer, &samp,
				       sizeof samp);
			}
			else
			{
				req[2].dbdata_buflen = snprintf(req[2].dbdata_buffer,
				                                req[2].dbdata_buflen,
				                                "%lu", samp);
			}
		}

		if (reqnum >= 4 && req[3].dbdata_buffer != NULL &&
		    req[3].dbdata_buflen != 0)
		{
			if ((req[3].dbdata_flags & DKIMF_DB_DATA_BINARY) != 0)
			{
				if (req[3].dbdata_buflen != sizeof when)
					return -1;
				memcpy(req[3].dbdata_buffer, &when,
				       sizeof when);
			}
			else
			{
				req[3].dbdata_buflen = snprintf(req[3].dbdata_buffer,
				                                req[3].dbdata_buflen,
				                                "%lu", when);
			}
		}

		if (reqnum >= 5 && req[4].dbdata_buffer != NULL &&
		    req[4].dbdata_buflen != 0)
		{
			if ((req[4].dbdata_flags & DKIMF_DB_DATA_BINARY) != 0)
			{
				if (req[4].dbdata_buflen != sizeof limit)
					return -1;
				memcpy(req[4].dbdata_buffer, &limit,
				       sizeof limit);
			}
			else
			{
				req[4].dbdata_buflen = snprintf(req[4].dbdata_buffer,
				                                req[4].dbdata_buflen,
				                                "%lu", limit);
			}
		}

		/* tag requests that weren't fulfilled */
		for (c = 5; c < reqnum; c++)
			req[c].dbdata_buflen = 0;

		return 0;
	  }
#endif /* _FFR_REPUTATION */

#ifdef _FFR_SOCKETDB
	  case DKIMF_DB_TYPE_SOCKET:
	  {
		int status;
		size_t len;
		size_t wlen;
		fd_set rfds;
		struct timeval timeout;
		struct iovec iov[2];
		struct dkimf_db_socket *sdb;
		char *tmp;
		char inbuf[BUFRSZ];

		sdb = (struct dkimf_db_socket *) db->db_handle;

		timeout.tv_sec = DKIMF_SOCKET_TIMEOUT;
		timeout.tv_usec = 0;

		iov[0].iov_base = buf;
		iov[0].iov_len = buflen;

		iov[1].iov_base = "\n";
		iov[1].iov_len = 1;

		/* single-thread readers */
		if (db->db_lock != NULL)
			(void) pthread_mutex_lock(db->db_lock);

		wlen = writev(sdb->sockdb_fd, iov, 2);
		if (wlen < buflen + 1)
		{
			db->db_status = errno;
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}

		FD_ZERO(&rfds);
		FD_SET(sdb->sockdb_fd, &rfds);

		dkimf_dstring_blank(sdb->sockdb_buf);

		for (;;)
		{
			status = select(sdb->sockdb_fd + 1, &rfds, NULL, NULL,
			                &timeout);
			if (status != 1)
			{
				db->db_status = errno;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return -1;
			}

			wlen = read(sdb->sockdb_fd, inbuf, sizeof inbuf);
			if (wlen == (size_t) -1)
			{
				db->db_status = errno;
				if (db->db_lock != NULL)
					(void) pthread_mutex_unlock(db->db_lock);
				return -1;
			}

			if (wlen == 0)
				break;

			dkimf_dstring_catn(sdb->sockdb_buf, inbuf, wlen);

			tmp = dkimf_dstring_get(sdb->sockdb_buf);
			len = dkimf_dstring_len(sdb->sockdb_buf);

			if (tmp[len - 1] == '\n')
				break;
		}

		if (len > 0 && exists != NULL)
			*exists = TRUE;

		if (dkimf_db_datasplit(tmp, len - 1, req, reqnum) != 0)
		{
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return -1;
		}
		else
		{
			if (db->db_lock != NULL)
				(void) pthread_mutex_unlock(db->db_lock);
			return 0;
		}
	  }
#endif /* _FFR_SOCKETDB */

#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		int status;
		struct dkimf_db_mdb *mdb;
		MDB_val key;
		MDB_val data;

		mdb = (struct dkimf_db_mdb *) db->db_handle;

		key.mv_size = buflen;
		key.mv_data = buf;

		status = mdb_get(mdb->mdb_txn, mdb->mdb_dbi, &key, &data);
		if (status == MDB_NOTFOUND)
		{
			if (exists != NULL)
				*exists = FALSE;
		}
		else if (status == 0)
		{
			if (exists != NULL)
				*exists = TRUE;

			if (dkimf_db_datasplit(data.mv_data, data.mv_size,
			                       req, reqnum) != 0)
				return -1;
		}
		else
		{
			db->db_status = status;
			return -1;
		}

		return 0;
	  }
#endif /* USE_MDB */

#ifdef USE_ERLANG
	  case DKIMF_DB_TYPE_ERLANG:
	  {
		int fd;
		int ret;
		int res_size;
		int res_index;
		int res_type;
		struct dkimf_db_erlang *e;
		ei_cnode ec;
		ei_x_buff args;
		ei_x_buff resp;

		e = (struct dkimf_db_erlang *) db->db_data;

		ei_x_new(&args);
		ei_x_new(&resp);

		ei_x_encode_list_header(&args, 1);
		ei_x_encode_binary(&args, buf, strlen(buf));
		ei_x_encode_empty_list(&args);

		fd = dkimf_db_erl_connect(db, &ec);
		if (fd < 0)
		{
			db->db_status = erl_errno;
			ei_x_free(&args);
			ei_x_free(&resp);
			return -1;
		}

		ret = ei_rpc(&ec, fd, e->erlang_module, e->erlang_function,
			     args.buff, args.index, &resp);
		close(fd);
		if (ret == -1)
		{
			db->db_status = erl_errno;
			ei_x_free(&args);
			ei_x_free(&resp);
			return ret;
		}

		ret = dkimf_db_erl_decode_response(&resp, "not_found", req,
	 	                                   reqnum, NULL, NULL);

		if (exists != NULL)
		{
			if (ret == 1)
				*exists = FALSE;
			else if (ret == 0)
				*exists = TRUE;
		}

		ei_x_free(&args);
		ei_x_free(&resp);

		if (ret == -1)
			db->db_status = erl_errno;

		return 0;
	  }
#endif /* USE_ERLANG */

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
# ifdef _FFR_DB_HANDLE_POOLS
		dkimf_db_hp_free((struct handle_pool *) db->db_handle);
# else /* _FFR_DB_HANDLE_POOLS */
		(void) odbx_finish((odbx_t *) db->db_handle);
# endif /* _FFR_DB_HANDLE_POOLS */
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

#ifdef USE_LIBMEMCACHED
	  case DKIMF_DB_TYPE_MEMCACHE:
	  {
		memcached_st *mcs;

		mcs = (memcached_st *) db->db_handle;

		memcached_free(mcs);
		free(db->db_data);
		return 0;
	  }
#endif /* USE_LIBMEMCACHED */

#ifdef _FFR_REPUTATION
	  case DKIMF_DB_TYPE_REPUTE:
	  {
		repute_close(db->db_data);
		free(db);
		return 0;
	  }
#endif /* _FFR_REPUTATION */

#ifdef _FFR_SOCKETDB
	  case DKIMF_DB_TYPE_SOCKET:
		if (db->db_handle != NULL)
		{
			struct dkimf_db_socket *sdb;

			sdb = (struct dkimf_db_socket *) db->db_handle;
			close(sdb->sockdb_fd);
		}
		free(db);
		return 0;
#endif /* _FFR_SOCKETDB */

#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		struct dkimf_db_mdb *mdb;

		mdb = db->db_data;

		if (db->db_cursor != NULL)
			mdb_cursor_close(db->db_cursor);

		mdb_txn_abort(mdb->mdb_txn);
		mdb_env_close(mdb->mdb_env);
		free(db->db_data);
		free(db);
	  	return 0;
	  }
#endif /* USE_MDB */

#ifdef USE_ERLANG
	  case DKIMF_DB_TYPE_ERLANG:
	  {
		struct dkimf_db_erlang *e;

		e = (struct dkimf_db_erlang *) db->db_data;
		dkimf_db_erl_free(e);
		return 0;
	  }
#endif /* USE_ERLANG */

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
	  case DKIMF_DB_TYPE_SOCKET:
		return strlcpy(err, strerror(db->db_status), errlen);

	  case DKIMF_DB_TYPE_REFILE:
		return regerror(db->db_status, db->db_data, err, errlen);

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
		return strlcpy(err, DB_STRERROR(db->db_status), errlen);
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
	  {
		char *p;

		strlcpy(err, odbx_error((odbx_t *) db->db_handle,
		                        db->db_status), errlen);
		for (p = err + strlen(err) - 1; p >= err; p--)
		{
			if (*p == '\n')
				*p = '\0';
			else
				break;
		}

		return strlen(err) + 1;
	  }
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

#ifdef USE_LIBMEMCACHED
	  case DKIMF_DB_TYPE_MEMCACHE:
		return strlcpy(err,
		               memcached_strerror((memcached_st *) db->db_handle,
		                                  db->db_status), errlen);
#endif /* USE_LIBMEMCACHED */

#ifdef _FFR_REPUTATION
	  case DKIMF_DB_TYPE_REPUTE:
	  {
		REPUTE rep;

		rep = (REPUTE) db->db_data;
		return strlcpy(err, repute_error(rep), errlen);
	  }
#endif /* _FFR_REPUTATION */

#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
		return strlcpy(err, mdb_strerror(db->db_status), errlen);
#endif /* USE_MDB */

#ifdef USE_ERLANG
	  case DKIMF_DB_TYPE_ERLANG:
		return strlcpy(err, strerror(db->db_status), errlen);
#endif /* USE_ERLANG */

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
	    db->db_type == DKIMF_DB_TYPE_SOCKET ||
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

		dsn = (struct dkimf_db_dsn *) db->db_data;
		result = (odbx_result_t *) db->db_cursor;

		/* purge old results cursor if known */
		if (result != NULL && first)
		{
			for (;;)
			{
				err = odbx_row_fetch(result);
				if (err == ODBX_ROW_DONE)
					break;
			}

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

		if (err == ODBX_ROW_DONE)
		{
			(void) odbx_result_finish(result);
			for (;;)
			{
				err = odbx_result((odbx_t *) db->db_handle,
				                  &result, NULL, 0);
				if (err == 0)
					break;
				(void) odbx_result_finish(result);
			}
			db->db_cursor = NULL;
			return 1;
		}

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
				if (c >= fields - 1)
				{
					req[c].dbdata_buflen = 0;
				}
				else
				{
					char *val;

					val = (char *) odbx_field_value(result,
					                                c + 1);

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

		return 0;
	  }
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		bool noattrs;
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

		if (ld == NULL)
		{
			int lderr;

			lderr = dkimf_db_open_ldap(&ld, ldap, NULL);
			if (lderr == LDAP_SUCCESS)
			{
				db->db_handle = ld;
			}
			else
			{
				db->db_status = lderr;
				pthread_mutex_unlock(&ldap->ldap_lock);
				return lderr;
			}
		}

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
			                     FALSE, query, sizeof query);
			dkimf_db_mkldapquery(ldap->ldap_descr->lud_filter, "*",
			                     TRUE, filter, sizeof filter);

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

		noattrs = FALSE;
		status = 0;
		for (c = 0; c < reqnum; c++)
		{
			if (ldap->ldap_descr->lud_attrs[c] == NULL)
				noattrs = TRUE;

			if (noattrs) 
			{
				if ((req[c].dbdata_flags & DKIMF_DB_DATA_OPTIONAL) == 0)
					status = -1;
				req[c].dbdata_buflen = (size_t) -1;
				continue;
			}

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

		return status;
	  }
#endif /* USE_LDAP */

#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		int status = 0;
		MDB_val k;
		MDB_val d;
		MDB_cursor *dbc;
		struct dkimf_db_mdb *mdb;
		char databuf[BUFRSZ + 1];

		mdb = (struct dkimf_db_mdb *) db->db_handle;

		dbc = db->db_cursor;
		if (dbc == NULL)
		{
			status = mdb_cursor_open(mdb->mdb_txn, mdb->mdb_dbi,
			                         &dbc);
			if (status != 0)
			{
				db->db_status = status;
				return -1;
			}

			db->db_cursor = dbc;
		}

		memset(&k, '\0', sizeof k);
		memset(&d, '\0', sizeof d);

		status = mdb_cursor_get(dbc, &k, &d,
		                        first ? MDB_FIRST : MDB_NEXT);
		if (status == MDB_NOTFOUND)
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
			memcpy(key, k.mv_data, MIN(k.mv_size, *keylen));
			*keylen = MIN(k.mv_size, *keylen);

			if (reqnum != 0)
			{
				if (dkimf_db_datasplit(d.mv_data, d.mv_size,
				                       req, reqnum) != 0)
                                        return -1;
			}

			return 0;
		}
	  }
#endif /* USE_MDB */

#ifdef USE_ERLANG
	  case DKIMF_DB_TYPE_ERLANG:
	  {
		int ret, fd;
		char *cursor;
		struct dkimf_db_erlang *e;
		ei_cnode ec;
		ei_x_buff args;
		ei_x_buff resp;

		e = (struct dkimf_db_erlang *) db->db_data;
		cursor = (char *) db->db_cursor;

		ei_x_new(&args);
		ei_x_new(&resp);

		if (!first && cursor == NULL)
			assert(0);

		if (first && cursor != NULL)
		{
			free(cursor);
			cursor = NULL;
		}

		ei_x_encode_list_header(&args, 1);
		if (first)
		{
			ei_x_encode_atom(&args, "first");
		}
		else
		{
			ei_x_encode_tuple_header(&args, 2);
			ei_x_encode_atom(&args, "next");
			ei_x_encode_binary(&args, cursor, strlen(cursor));
		}
		ei_x_encode_empty_list(&args);

		fd = dkimf_db_erl_connect(db, &ec);
		if (fd < 0)
		{
			ei_x_free(&args);
			ei_x_free(&resp);
			return -1;
		}

		ret = ei_rpc(&ec, fd, e->erlang_module, e->erlang_function,
			     args.buff, args.index, &resp);
		close(fd);
		if (ret == -1)
		{
			ei_x_free(&args);
			ei_x_free(&resp);
			return -1;
		}

		ret = dkimf_db_erl_decode_response(&resp, "$end_of_table",
		                                   req, reqnum, key, keylen);

		ei_x_free(&args);
		ei_x_free(&resp);

		switch (ret)
		{
		  case -1:
		  {
			  if (cursor != NULL)
				  free(cursor);
			  return -1;
		  }

		  case 1:
		  {
			  free(cursor);
			  db->db_cursor = NULL;
			  return 1;
		  }

		  case 0:
		  {
			  if (key != NULL && keylen != NULL)
			  {
				  size_t cursize;
				  cursize = *keylen + 1;
				  cursor = malloc(cursize);
				  if (cursor == NULL)
					  return -1;
				  strlcpy(cursor, key, cursize);
				  db->db_cursor = cursor;
			  }

			  return 0;
		  }
		}

		assert(cursor != NULL);
	  }
#endif /* USE_ERLANG */

	  default:
		assert(0);
		return -1;		/* to silence compiler warnings */
	}
}

/*
**  DKIMF_DB_MKARRAY_BASE -- make a (char *) array treating the DB as a
**                           delta to a provided base
**
**  Parameters:
**  	db -- a DKIMF_DB handle
**  	a -- array (returned)
**  	base -- base array
** 
**  Return value:
**  	Length of the created array, or -1 on error/empty.
*/

static int
dkimf_db_mkarray_base(DKIMF_DB db, char ***a, const char **base)
{
	_Bool found;
	int c;
	int status;
	int nalloc = 0;
	int nout = 0;
	int nbase;
	size_t buflen;
	char **out = NULL;
	char buf[BUFRSZ + 1];

	assert(db != NULL);
	assert(a != NULL);

	/* count base elements */
	for (nbase = 0; base[nbase] != NULL; nbase++)
		continue;

	/* initialize output array */
	nalloc = MAX(nbase, 16);
	out = (char **) malloc(sizeof(char *) * nalloc);
	if (out == NULL)
		return -1;
	out[0] = NULL;

	/* copy the base array modulo removals in the DB */
	for (c = 0; c < nbase; c++)
	{
		memset(buf, '\0', sizeof buf);

		snprintf(buf, sizeof buf, "-%s", base[c]);

		found = FALSE;
		status = dkimf_db_get(db, buf, 0, NULL, 0, &found);
		if (status != 0)
		{
			for (c = 0; c < nout; c++)
				free(out[c]);
			free(out);
			return -1;
		}

		if (!found)
		{
			if (nout == nalloc - 1)
			{
				char **new;

				new = (char **) realloc(out,
				                        sizeof(char *) * (nalloc * 2));
				if (new == NULL)
				{
					for (c = 0; c < nout; c++)
						free(out[c]);
					free(out);
					return -1;
				}

				out = new;
				nalloc *= 2;
			}

			out[nout] = strdup(base[c]);
			if (out[nout] == NULL)
			{
				for (c = 0; c < nout; c++)
					free(out[c]);
				free(out);
				return -1;
			}

			nout++;
			out[nout] = NULL;
		}
	}

	/* now add any in the DB that aren't in the array */
	for (c = 0; ; c++)
	{
		buflen = sizeof buf - 1;
		memset(buf, '\0', sizeof buf);

		status = dkimf_db_walk(db, (c == 0), buf, &buflen, NULL, 0);
		if (status == -1)
		{
			for (c = 0; c < nout; c++)
				free(out[c]);
			free(out);
			return -1;
		}
		else if (status == 1)
		{
			break;
		}
		else if (buf[0] != '+')
		{
			continue;
		}

		if (nout == nalloc - 1)
		{
			char **new;

			new = (char **) realloc(out,
			                        sizeof(char *) * (nalloc * 2));
			if (new == NULL)
			{
				for (c = 0; c < nout; c++)
					free(out[c]);
				free(out);
				return -1;
			}

			out = new;
			nalloc *= 2;
		}

		out[nout] = strdup(&buf[1]);
		if (out[nout] == NULL)
		{
			for (c = 0; c < nout; c++)
				free(out[c]);
			free(out);
			return -1;
		}

		nout++;
		out[nout] = NULL;
	}

	*a = out;
	return nout;
}

/*
**  DKIMF_DB_MKARRAY -- make a (char *) array of DB contents
**
**  Parameters:
**  	db -- a DKIMF_DB handle
**  	a -- array (returned)
**  	base -- base array (may be NULL)
**
**  Return value:
**  	Length of the created array, or -1 on error/empty.
*/

int
dkimf_db_mkarray(DKIMF_DB db, char ***a, const char **base)
{
	_Bool found;
	int status;
	char **out = NULL;

	assert(db != NULL);
	assert(a != NULL);

	if (db->db_type == DKIMF_DB_TYPE_REFILE ||
	    db->db_type == DKIMF_DB_TYPE_SOCKET ||
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

	found = FALSE;
	status = dkimf_db_get(db, "*", 0, NULL, 0, &found);
	if (status != 0)
		return -1;
	if (found && base != NULL)
		return dkimf_db_mkarray_base(db, a, base);

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

/*
**  DKIMF_DB_CHOWN -- set ownership and permissions on a DB
**
**  Parameters:
**  	db -- DKIMF_DB handle
**  	uid -- target uid
**
**  Return value:
**  	1 -- success
**  	0 -- not a DB that can be chowned
**  	-1 -- fchown() failed
*/

int
dkimf_db_chown(DKIMF_DB db, uid_t uid)
{
#ifdef USE_DB
	int fd = -1;
	int status = 0;
	DB *bdb;
#endif /* USE_DB */

	assert(db != NULL);
	assert(uid >= 0);

	if (dkimf_db_type(db) != DKIMF_DB_TYPE_BDB ||
	    (db->db_flags & DKIMF_DB_FLAG_READONLY) != 0 ||
	    (db->db_flags & DKIMF_DB_FLAG_NOFDLOCK) != 0)
		return 0;

#ifdef USE_DB
	bdb = (DB *) db->db_handle;

# if DB_VERSION_CHECK(2,0,0)
	status = bdb->fd(bdb, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
	fd = bdb->fd(bdb);
# endif /* DB_VERSION_CHECK(2,0,0) */

	if (status != 0 || fd == -1)
		return 0;

	if (fchown(fd, uid, -1) != 0)
		return -1;
	else
		return 1;

#else /* USE_DB */

	return 0;

#endif /* USE_DB */
}
