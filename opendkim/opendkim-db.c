/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-db.c,v 1.29.2.24 2010/01/13 20:08:03 cm-msk Exp $
*/

#ifndef lint
static char opendkim_db_c_id[] = "@(#)$Id: opendkim-db.c,v 1.29.2.24 2010/01/13 20:08:03 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/file.h>
#include <stdbool.h>
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

/* libopendkim includes */
#include <dkim.h>
#include <dkim-strl.h>

/* opendkim includes */
#include "opendkim-db.h"
#include "opendkim.h"
#include "util.h"

/* macros */
#define	DEFARRAYSZ		16
#define DKIMF_DB_MODE		0644
#define DKIMF_LDAP_MAXURIS	8
#define DKIMF_LDAP_TIMEOUT	5

#define	DKIMF_DB_IFLAG_FREEARRAY 0x01

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
	void *			db_handle;
	void *			db_data;
	void *			db_cursor;
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
	pthread_mutex_t		ldap_lock;
};
#endif /* USE_LDAP */

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
	{ NULL,			DKIMF_DB_TYPE_UNKNOWN },
};


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
		interact->result = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_BINDPW);
		interact->len = strlen(interact->result);
		break;

	  case SASL_CB_GETREALM:
		interact->result = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_AUTHREALM);
		interact->len = strlen(interact->result);
		break;

	  case SASL_CB_AUTHNAME:
		interact->result = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_AUTHNAME);
		interact->len = strlen(interact->result);
		break;

	  case SASL_CB_USER:
		interact->result = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_AUTHUSER);
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
**  	None.
*/

static void
dkimf_db_datasplit(char *buf, size_t buflen,
                   DKIMF_DBDATA req, unsigned int reqnum)
{
	int ridx;
	size_t clen;
	size_t remain;
	char *p;
	char *q;

	assert(buf != NULL);

	if (req == NULL || reqnum == 0)
		return;

	ridx = 0;
	clen = 0;
	remain = buflen;
	q = req[ridx].dbdata_buffer;

	for (p = buf; *p != '\0' && ridx < reqnum; p++)
	{
		/*
		**  Break at ":" except in last one or at the end of complete
		**  binary ones.
		*/

		if ((*p == ':' && ridx < reqnum - 1) ||
		    (req[ridx].dbdata_flags & DKIMF_DB_DATA_BINARY &&
		     clen == req[ridx].dbdata_buflen))
		{
			req[ridx].dbdata_buflen = clen;
			ridx++;
			clen = 0;
			q = req[ridx].dbdata_buffer;

			continue;
		}

		/* copy byte */
		if (clen < req[ridx].dbdata_buflen)
		{
			*q = *p;
			q++;
		}

		clen++;
	}

	/* mark the ones that got no data */
	if (ridx < reqnum - 1)
	{
		int c;

		for (c = ridx + 1; c < reqnum; c++)
			req[c].dbdata_buflen = 0;
	}
}

#ifdef USE_LDAP
/*
**  DKIMF_DB_MKLDAPQUERY -- generate an LDAP query
**
**  Parameters:
**  	ldap -- LDAP data handle
**  	buf -- parameter (the actual query)
**  	buflen -- length of data in "buf"
**  	query -- destination string
**  	qlen -- size of "query"
**
**  Return value:
**  	None.
**
**  Notes:
**  	Should report overflows.
*/

static void
dkimf_db_mkldapquery(struct dkimf_db_ldap *ldap, char *buf, size_t buflen,
                     char *query, size_t qlen)
{
	char last = '\0';
	char *p;
	char *b;
	char *q;
	char *pend;
	char *bend;
	char *qend;

	assert(ldap != NULL);
	assert(buf != NULL);
	assert(query != NULL);

	p = ldap->ldap_descr->lud_dn;
	pend = p + strlen(p) - 1;
	q = query;
	qend = query + qlen - 1;
	bend = buf + buflen - 1;

	while (p <= pend && q <= qend)
	{
		if (last == '$')
		{
			if (*p == 'd')
			{
				for (b = buf; b <= bend && q <= qend; b++)
					*q++ = *b;
			}
			else
			{
				*q++ = *p;
			}
		}
		else if (*p != '$')
		{
			*q++ = *p;
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
		if (isascii(*p) && ispunct(*p))
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
*/

int
dkimf_db_open(DKIMF_DB *db, char *name, u_int flags, pthread_mutex_t *lock)
{
	DKIMF_DB new;
	char *p;

	assert(db != NULL);
	assert(name != NULL);

	new = (DKIMF_DB) malloc(sizeof(struct dkimf_db));
	if (new == NULL)
		return -1;

	memset(new, '\0', sizeof(struct dkimf_db));

	new->db_lock = lock;
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
			return 1;
		}

		p++;
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
			return 2;
		}

		tmp = strdup(p);
		if (tmp == NULL)
			return -1;

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
						if (list != NULL)
							dkimf_db_list_free(list);
						free(tmp);
						return -1;
					}

					newl->db_list_key = strdup(p);
					if (newl->db_list_key == NULL)
					{
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(tmp);
						return -1;
					}

					newl->db_list_value = strdup(q);
					if (newl->db_list_value == NULL)
					{
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(tmp);
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
					if (list != NULL)
						dkimf_db_list_free(list);
					free(tmp);
					return -1;
				}

				newl->db_list_key = strdup(p);
				if (newl->db_list_key == NULL)
				{
					free(newl);
					if (list != NULL)
						dkimf_db_list_free(list);
					free(tmp);
					return -1;
				}

				if (eq != NULL)
				{
					newl->db_list_value = strdup(eq + 1);
					if (newl->db_list_value == NULL)
					{
						free(newl->db_list_key);
						free(newl);
						free(tmp);
						if (list != NULL)
							dkimf_db_list_free(list);
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
		size_t len;
		FILE *f;
		char *key;
		char *value;
		struct dkimf_db_list *list = NULL;
		struct dkimf_db_list *next = NULL;
		struct dkimf_db_list *newl;
		char line[BUFRSZ + 1];

		if ((flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			free(new);
			errno = EINVAL;
			return 2;
		}

		f = fopen(p, "r");
		if (f == NULL)
		{
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
				if (list != NULL)
					dkimf_db_list_free(list);
				fclose(f);
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
						if (list != NULL)
							dkimf_db_list_free(list);
						return -1;
					}

					newl->db_list_key = strdup(p);
					if (newl->db_list_key == NULL)
					{
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						return -1;
					}

					newl->db_list_value = strdup(q);
					if (newl->db_list_value == NULL)
					{
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
					free(newl);
					if (list != NULL)
						dkimf_db_list_free(list);
					fclose(f);
					return -1;
				}

				if (value != NULL)
				{
					newl->db_list_value = strdup(value);
					if (newl->db_list_value == NULL)
					{
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						fclose(f);
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
		int n;
		int c;
		int status;
		int reflags;
		size_t len;
		FILE *f;
		char *end;
		char *colon;
		struct dkimf_db_relist *list = NULL;
		struct dkimf_db_relist *newl;
		char line[BUFRSZ + 1];
		char patbuf[BUFRSZ + 1];

		if ((flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			free(new);
			errno = EINVAL;
			return 2;
		}

		f = fopen(p, "r");
		if (f == NULL)
		{
			free(new);
			return -1;
		}

		reflags = REG_EXTENDED;
		if ((new->db_flags & DKIMF_DB_FLAG_ICASE) != 0)
			reflags |= REG_ICASE;

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

			colon = strchr(line, ':');
			if (colon != NULL)
				*colon = '\0';

			dkimf_trimspaces((u_char *) line);
			if (strlen(line) == 0)
				continue;

			newl = (struct dkimf_db_relist *) malloc(sizeof(struct dkimf_db_relist));
			if (newl == NULL)
			{
				if (list != NULL)
					dkimf_db_relist_free(list);
				fclose(f);
				return -1;
			}

			memset(patbuf, '\0', sizeof patbuf);
			end = patbuf + sizeof patbuf;
			patbuf[0] = '^';

			if (!dkimf_mkregexp(line, patbuf, sizeof patbuf))
			{
				if (list != NULL)
					dkimf_db_relist_free(list);
				fclose(f);
				return -1;
			}

			status = regcomp(&newl->db_relist_re, patbuf, reflags);
			if (status != 0)
			{
				new->db_data = (void *) &newl->db_relist_re;
				/* XXX -- do something */
				if (list != NULL)
					dkimf_db_relist_free(list);
				fclose(f);
				return -1;
			}

			if (colon != NULL)
				newl->db_relist_data = strdup(colon + 1);
			else
				newl->db_relist_data = NULL;

			newl->db_relist_next = list;
			list = newl;
		}

		fclose(f);

		new->db_handle = list;

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
# elif DB_VERSION_CHECK(3,0,0)
		status = db_open(p, bdbtype, dbflags, DKIMF_DB_MODE,
		                 NULL, NULL, &newdb);
# else /* DB_VERSION_MAJOR < 3 */
		newdb = dbopen(p,
		               (flags & DKIMF_DB_FLAG_READONLY ? O_RDONLY
		                                                : (O_CREAT|O_RDWR)),
		               DKIMF_DB_MODE, bdbtype, NULL);
		if (newdb == NULL)
			status = errno;
# endif /* DB_VERSION_CHECK */

		if (status != 0)
			return 3;

		new->db_handle = newdb;

		break;
	  }
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
	  {
		_Bool found;
		int err;
		struct dkimf_db_dsn *dsn;
		char *q;
		char *r;
		char *eq;
		char *tmp;
		odbx_t *odbx;

		dsn = (struct dkimf_db_dsn *) malloc(sizeof(struct dkimf_db_dsn));
		if (dsn == NULL)
			return -1;

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
			free(dsn);
			return -1;
		}

		q = strchr(tmp, ':');
		if (q == NULL)
		{
			free(dsn);
			free(tmp);
			return -1;
		}

		*q = '\0';
		strlcpy(dsn->dsn_backend, tmp, sizeof dsn->dsn_backend);

		q++;
		if (*q != '/' || *(q + 1) != '/')
		{
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
					free(dsn);
					free(tmp);
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
				free(dsn);
				free(tmp);
				return -1;
			}
		}

		if (dsn->dsn_host[0] == '\0')
		{
			free(dsn);
			free(tmp);
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
			free(dsn);
			free(tmp);
			return -1;
		}

# define STRORNULL(x)	((x)[0] == '\0' ? NULL : (x))

		/* create odbx handle */
		err = odbx_init(&odbx,
		                STRORNULL(dsn->dsn_backend),
		                STRORNULL(dsn->dsn_host),
		                STRORNULL(dsn->dsn_port));
		if (err < 0)
		{
			free(dsn);
			free(tmp);
			return -1;
		}

		/* create bindings */
		err = odbx_bind(odbx, STRORNULL(dsn->dsn_dbase),
		                      STRORNULL(dsn->dsn_user),
		                      STRORNULL(dsn->dsn_password),
		                      ODBX_BIND_SIMPLE);
		if (err < 0)
		{
			(void) odbx_finish(odbx);
			free(dsn);
			free(tmp);
			return -1;
		}

		/* store handle */
		new->db_handle = (void *) odbx;
		new->db_data = (void *) dsn;

		/* clean up */
		free(tmp);
	  }
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		_Bool found;
		_Bool usetls = FALSE;
		int c;
		int err;
		int v = LDAP_VERSION3;
		size_t rem;
		struct dkimf_db_ldap *ldap;
		LDAP *ld;
		char *q;
		char *r;
		char *u;
		LDAPURLDesc *descr;
		char *uris[DKIMF_LDAP_MAXURIS];

		memset(uris, '\0', sizeof uris);

		p = strdup(name);
		if (p == NULL)
			return -1;

		/* make sure they're all valid LDAP URIs */
		for (q = strtok_r(p, " \t", &r), c = 0;
		     q != NULL;
		     q = strtok_r(NULL, " \t", &r), c++)
		{
			if (ldap_is_ldap_url(q) == 0)
			{
				free(p);
				return -1;
			}

			/* store the first N of them */
			if (c < DKIMF_LDAP_MAXURIS)
				uris[c] = q;
		}

		ldap = (struct dkimf_db_ldap *) malloc(sizeof(struct dkimf_db_ldap));
		if (ldap == NULL)
		{
			free(p);
			return -1;
		}

		memset(ldap, '\0', sizeof ldap);
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

		err = ldap_url_parse(uris[0], &ldap->ldap_descr);
		if (err != 0)
		{
			free(ldap);
			free(p);
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

			rem -= snprintf(q, rem, "%s://%s:%d",
			                descr->lud_scheme,
			                descr->lud_host,
			                descr->lud_port);

			if (rem < 0)
			{
				free(ldap);
				free(p);
				return -1;
			}

			ldap_free_urldesc(descr);
		}

		/* create LDAP handle */
		err = ldap_initialize(&ld, ldap->ldap_urilist);
		if (err != LDAP_SUCCESS)
		{
			free(ldap);
			free(p);
			return -1;
		}

		/* set LDAP version */
		err = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &v);
		if (err != LDAP_OPT_SUCCESS)
		{
			ldap_unbind_ext(ld, NULL, NULL);
			free(ldap);
			free(p);
			return -1;
		}

		/* attempt TLS if requested */
		q = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_USETLS);
		if (q != NULL && (*q == 'y' || *q == 'Y') &&
		    strcasecmp(ldap->ldap_descr->lud_scheme, "ldaps") != 0)
		{
			err = ldap_start_tls_s(ld, NULL, NULL);
			if (err != LDAP_SUCCESS)
			{
				ldap_unbind_ext(ld, NULL, NULL);
				free(ldap);
				free(p);
				return -1;
			}
		}

		/* attempt binding */
		q = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_AUTHMECH);
		u = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_BINDUSER);
		if (q == NULL || strcasecmp(q, "none") == 0 ||
		    strcasecmp(q, "simple") == 0)
		{
			struct berval passwd;

			r = dkimf_get_ldap_param(DKIMF_LDAP_PARAM_BINDPW);
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

			err = ldap_sasl_bind_s(ld, u, q, &passwd,
			                       NULL, NULL, NULL);
			if (err != LDAP_SUCCESS)
			{
				ldap_unbind_ext(ld, NULL, NULL);
				free(ldap);
				free(p);
				return -1;
			}
		}
		else
		{
#ifdef USE_SASL
			err = ldap_sasl_interactive_bind_s(ld,
			                                   u,	/* bind user */
			                                   q,	/* SASL mech */
			                                   NULL, /* controls */
			                                   NULL, /* controls */
			                                   LDAP_SASL_QUIET, /* flags */
			                                   dkimf_db_saslinteract, /* callback */
			                                   NULL);
			if (err != LDAP_SUCCESS)
			{
				ldap_unbind_ext(ld, NULL, NULL);
				free(ldap);
				free(p);
				return -1;
			}
#else /* USE_SASL */
			/* unknown auth mechanism */
			ldap_unbind_ext(ld, NULL, NULL);
			free(ldap);
			free(p);
			return -1;
#endif /* USE_SASL */
		}

		pthread_mutex_init(&ldap->ldap_lock, NULL);

		/* store handle */
		new->db_handle = (void *) ld;
		new->db_data = (void *) ldap;

		/* clean up */
		free(p);
	  }
#endif /* USE_LDAP */
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
#ifdef USE_DB
	DBT q;
	int fd;
	int status;
	int ret;
	DB *bdb;
#endif /* USE_DB */

	assert(db != NULL);
	assert(buf != NULL);

	if (db->db_type == DKIMF_DB_TYPE_FILE ||
	    db->db_type == DKIMF_DB_TYPE_CSL || 
	    db->db_type == DKIMF_DB_TYPE_DSN || 
	    db->db_type == DKIMF_DB_TYPE_LDAP || 
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
			return -1;
		}
# endif /* LOCK_UN */
	}

	if (db->db_lock != NULL)
		(void) pthread_mutex_unlock(db->db_lock);

	return ret;
#endif /* USE_DB */
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
#ifdef USE_DB
	DBT d;
	DBT q;
	int fd;
	int status;
	int ret;
	DB *bdb;
#endif /* USE_DB */

	assert(db != NULL);
	assert(buf != NULL);
	assert(outbuf != NULL);

	if (db->db_type == DKIMF_DB_TYPE_FILE ||
	    db->db_type == DKIMF_DB_TYPE_CSL || 
	    db->db_type == DKIMF_DB_TYPE_DSN || 
	    db->db_type == DKIMF_DB_TYPE_LDAP || 
	    db->db_type == DKIMF_DB_TYPE_REFILE)
		return EINVAL;

#ifdef USE_DB
	bdb = (DB *) db->db_handle;

	memset(&d, 0, sizeof d);
	memset(&q, 0, sizeof q);

	d.data = outbuf;
	d.size = outbuflen;
#if DB_VERSION_CHECK(2,0,0)
	d.ulen = d.size;
	d.flags = DB_DBT_USERMEM;
#endif /* DB_VERSION_CHECK(2,0,0) */

	q.data = (char *) buf;
	q.size = (buflen == 0 ? strlen(q.data) : buflen);
#if DB_VERSION_CHECK(2,0,0)
	q.ulen = q.size;
	q.flags = DB_DBT_USERMEM;
#endif /* DB_VERSION_CHECK(2,0,0) */

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
			return -1;
		}
# endif /* LOCK_EX */
	}

# if DB_VERSION_CHECK(2,0,0)
	status = bdb->put(bdb, NULL, &q, &d, 0);
	if (status == 0)
		ret = 0;
	else
		ret = status;
# else /* DB_VERSION_CHECK(2,0,0) */
	status = bdb->put(bdb, &q, &d, 0);
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
			return -1;
		}
# endif /* LOCK_UN */
	}

	if (db->db_lock != NULL)
		(void) pthread_mutex_unlock(db->db_lock);

	return ret;
#endif /* USE_DB */
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
	int status;
	int ret;
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

			if (matched)
			{
				if ((db->db_flags & DKIMF_DB_FLAG_MATCHBOTH) == 0 ||
				    list->db_list_value == NULL)
					break;
			}

			if ((db->db_flags & DKIMF_DB_FLAG_MATCHBOTH) == 0 ||
			    reqnum == 0)
				continue;

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
				dkimf_db_datasplit(list->db_list_value,
				                   strlen(list->db_list_value),
				                   req, reqnum);
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
					dkimf_db_datasplit(list->db_relist_data,
					                   strlen(list->db_relist_data),
					                   req, reqnum);
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
		d.flags = DB_DBT_USERMEM|DB_DBT_PARTIAL;
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

		/* XXX -- allow multiple readers? */
		if (db->db_lock != NULL)
			(void) pthread_mutex_lock(db->db_lock);

		if (status == 0 && fd != -1)
		{
# ifdef LOCK_SH
			status = flock(fd, LOCK_SH);
			if (status != 0)
			{
				db->db_status = status;
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
		
			if (reqnum != 0)
			{
				dkimf_db_datasplit(databuf, sizeof databuf,
				                   req, reqnum);
			}

			ret = 0;
		}
		else if (status == DB_NOTFOUND)
		{
			if (exists != NULL)
				*exists = FALSE;
			ret = 0;
		}
		else
		{
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

			if (reqnum != 0)
				dkimf_db_datasplit(databuf, clen, req, reqnum);

			ret = 0;
		}
		else
		{
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
		u_long elen;
		odbx_result_t *result;
		struct dkimf_db_dsn *dsn;
		char query[BUFRSZ];
		char escaped[BUFRSZ];

		dsn = (struct dkimf_db_dsn *) db->db_data;

		memset(&elen, '\0', sizeof elen);
		elen = sizeof escaped - 1;
		err = odbx_escape((odbx_t *) db->db_handle, buf,
		                  (buflen == 0 ? strlen(buf) : buflen),
		                  escaped, &elen);
		if (err < 0)
		{
			db->db_status = err;
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
			return err;
		}

		err = odbx_result((odbx_t *) db->db_handle,
		                  &result, NULL, 0);
		if (err < 0)
		{
			(void) odbx_result_finish(result);
			db->db_status = err;
			return err;
		}
		else if (err == ODBX_RES_DONE)
		{
			if (exists != NULL)
				*exists = FALSE;
			(void) odbx_result_finish(result);
			return 0;
		}

		err = odbx_row_fetch(result);
		if (err < 0)
		{
			(void) odbx_result_finish(result);
			db->db_status = err;
			return err;
		}
		else if (err == ODBX_RES_DONE)
		{
			if (exists != NULL)
				*exists = FALSE;
			(void) odbx_result_finish(result);
			return 0;
		}

		fields = odbx_column_count(result);
		if (fields == 0)
		{
			/* XXX -- huh? */
			(void) odbx_result_finish(result);
			return -1;
		}

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

					req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
					                               val,
					                               req[c].dbdata_buflen);
				}
			}
		}

		(void) odbx_result_finish(result);

		return 0;
	  }
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		int c;
		LDAP *ld;
		LDAPMessage *result;
		LDAPMessage *e;
		struct dkimf_db_ldap *ldap;
		struct berval **vals;
		char query[BUFRSZ];
		struct timeval timeout;

		ld = (LDAP *) db->db_handle;
		ldap = (struct dkimf_db_ldap *) db->db_data;

		pthread_mutex_lock(&ldap->ldap_lock);

		dkimf_db_mkldapquery(ldap, buf, buflen, query, sizeof query);

		timeout.tv_sec = ldap->ldap_timeout;
		timeout.tv_usec = 0;

		status = ldap_search_ext_s(ld, query,
		                           ldap->ldap_descr->lud_scope,
		                           ldap->ldap_descr->lud_filter,
		                           ldap->ldap_descr->lud_attrs,
		                           0, NULL, NULL,
		                           &timeout, 0, &result);
		if (status != LDAP_SUCCESS)
		{
			db->db_status = status;
			pthread_mutex_unlock(&ldap->ldap_lock);
			return status;
		}

		e = ldap_first_entry(ld, result);
		if (e == NULL)
		{
			if (exists != NULL)
				*exists = FALSE;
			pthread_mutex_unlock(&ldap->ldap_lock);
			return 0;
		}

		if (exists != NULL)
			*exists = TRUE;

		for (c = 0; c < reqnum; c++)
		{
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

		ldap_msgfree(result);
		pthread_mutex_unlock(&ldap->ldap_lock);
		return 0;
	  }
#endif /* USE_LDAP */

	  default:
		assert(0);
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
**  	None.
*/

void
dkimf_db_close(DKIMF_DB db)
{
	assert(db != NULL);

	if (db->db_array != NULL)
	{
		int c;

		if ((db->db_iflags & DKIMF_DB_IFLAG_FREEARRAY) != 0)
		{
			for (c = 0; db->db_array != NULL; c++)
				free(db->db_array[c]);
		}
		free(db->db_array);
		db->db_array = NULL;
	}

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
		dkimf_db_list_free(db->db_handle);
		free(db);
		break;

	  case DKIMF_DB_TYPE_REFILE:
		dkimf_db_relist_free(db->db_handle);
		free(db);
		break;

#ifdef USE_DB
	  case DKIMF_DB_TYPE_BDB:
# if DB_VERSION_CHECK(2,0,0)
		if (db->db_cursor != NULL)
			((DBC *) (db->db_cursor))->c_close((DBC *) db->db_cursor);
# endif /* DB_VERSION_CHECK(2,0,0) */
		DKIMF_DBCLOSE((DB *) (db->db_handle));
		break;
#endif /* USE_DB */

#ifdef USE_ODBX
	  case DKIMF_DB_TYPE_DSN:
		(void) odbx_finish((odbx_t *) db->db_handle);
		free(db->db_data);
		break;
#endif /* USE_ODBX */

#ifdef USE_LDAP
	  case DKIMF_DB_TYPE_LDAP:
	  {
		struct dkimf_db_ldap *ldap;

		ldap = (struct dkimf_db_ldap *) db->db_data;

		ldap_unbind_ext((LDAP *) db->db_handle, NULL, NULL);
		pthread_mutex_destroy(&ldap->ldap_lock);
		(void) ldap_free_urldesc(ldap->ldap_descr);
		free(db->db_data);
		break;
	  }
#endif /* USE_LDAP */

	  default:
		assert(0);
	}

	/* NOTREACHED */
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

	  default:
		assert(0);
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

	if (db->db_type == DKIMF_DB_TYPE_REFILE)
		return -1;

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_CSL:
	  case DKIMF_DB_TYPE_FILE:
	  {
		size_t out;
		struct dkimf_db_list *list;

		if (first)
			list = (struct dkimf_db_list *) db->db_handle;
		else
			list = (struct dkimf_db_list *) db->db_cursor;

		if (list == NULL)
			return 1;

		if (key != NULL)
		{
			assert(keylen != NULL);

			*keylen = strlcpy(key, list->db_list_key, *keylen);
		}

		if (reqnum != 0)
		{
			if (list->db_list_value != NULL)
			{
				dkimf_db_datasplit(list->db_list_value,
				                   strlen(list->db_list_value),
				                   req, reqnum);
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
				memcpy(key, k.data, MIN(k.size, *keylen));

			if (reqnum != 0)
			{
				dkimf_db_datasplit(databuf, sizeof databuf,
				                   req, reqnum);
			}
# endif /* ! DB_VERSION_CHECK(2,0,0) */

			if (keylen != NULL)
				*keylen = k.size;

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
			/* XXX -- huh? */
			(void) odbx_result_finish(result);
			db->db_cursor = NULL;
			return -1;
		}

		if (key != NULL)
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

	  default:
		assert(0);
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

	if (db->db_type == DKIMF_DB_TYPE_REFILE)
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
		int c;
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
			else if (nr + 1 == na)
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

				out[nr] = strdup(keybuf);
				if (out[nr] == NULL)
				{
					for (c = 0; c < nr; c++)
						free(out[c]);
					free(out);
					return -1;
				}

				nr++;
				na = newsz;
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
