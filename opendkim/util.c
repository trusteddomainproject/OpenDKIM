/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2015, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <assert.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#ifdef _FFR_REPLACE_RULES
# include <regex.h>
#endif /* _FFR_REPLACE_RULES */

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif /* HAVE_PATHS_H */
#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif /* ! _PATH_DEVNULL */

#ifdef SOLARIS
# if SOLARIS <= 20600
#  define socklen_t size_t
# endif /* SOLARIS <= 20600 */
#endif /* SOLARIS */

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendkim includes */
#include "opendkim.h"
#include "util.h"
#include "opendkim-db.h"

/* macros */
#define	DEFARGS		8

/* missing definitions */
#ifndef INADDR_NONE
# define INADDR_NONE	((uint32_t) -1)
#endif /* ! INADDR_NONE */

/* globals */
#ifdef POPAUTH
static pthread_mutex_t pop_lock;
#endif /* POPAUTH */

static char *optlist[] =
{
#if DEBUG
	"DEBUG",
#endif /* DEBUG */

#if POPAUTH
	"POPAUTH",
#endif /* POPAUTH */

#if QUERY_CACHE
	"QUERY_CACHE",
#endif /* QUERY_CACHE */

#if USE_DB
	"USE_DB",
#endif /* USE_DB */

#if USE_ERLANG
	"USE_ERLANG",
#endif /* USE_ERLANG */

#if USE_JANSSON
	"USE_JANSSON",
#endif /* USE_JANSSON */

#if USE_LDAP
	"USE_LDAP",
#endif /* USE_LDAP */

#if USE_LUA
	"USE_LUA",
#endif /* USE_LUA */

#if USE_MDB
	"USE_MDB",
#endif /* USE_MDB */

#if USE_ODBX
	"USE_ODBX",
#endif /* USE_ODBX */

#if USE_UNBOUND
	"USE_UNBOUND",
#endif /* USE_UNBOUND */

#ifdef _FFR_ADSP_LISTS
	"_FFR_ADSP_LISTS",
#endif /* _FFR_ADSP_LISTS */

#ifdef _FFR_ATPS
	"_FFR_ATPS",
#endif /* _FFR_ATPS */

#ifdef _FFR_CONDITIONAL
	"_FFR_CONDITIONAL",
#endif /* _FFR_CONDITIONAL */

#ifdef _FFR_DEFAULT_SENDER
	"_FFR_DEFAULT_SENDER",
#endif /* _FFR_DEFAULT_SENDER */

#if _FFR_DIFFHEADERS
	"_FFR_DIFFHEADERS",
#endif /* _FFR_DIFFHEADERS */

#if _FFR_IDENTITY_HEADER
	"_FFR_IDENTITY_HEADER",
#endif /* _FFR_IDENTITY_HEADER */

#if _FFR_LDAP_CACHING
	"_FFR_LDAP_CACHING",
#endif /* _FFR_LDAP_CACHING */

#if _FFR_LUA_ONLY_SIGNING
	"_FFR_LUA_ONLY_SIGNING",
#endif /* _FFR_LUA_ONLY_SIGNING */

#if _FFR_POSTGRESQL_RECONNECT_HACK
	"_FFR_POSTGRESQL_RECONNECT_HACK",
#endif /* _FFR_POSTGRESQL_RECONNECT_HACK */

#if _FFR_RATE_LIMIT
	"_FFR_RATE_LIMIT",
#endif /* _FFR_RATE_LIMIT */

#if _FFR_RBL
	"_FFR_RBL",
#endif /* _FFR_RBL */

#if _FFR_REPLACE_RULES
	"_FFR_REPLACE_RULES",
#endif /* _FFR_REPLACE_RULES */

#if _FFR_REPRRD
	"_FFR_REPRRD",
#endif /* _FFR_REPRRD */

#if _FFR_REPUTATION
	"_FFR_REPUTATION",
#endif /* _FFR_REPUTATION */

#if _FFR_RESIGN
	"_FFR_RESIGN",
#endif /* _FFR_RESIGN */

#if _FFR_SENDER_MACRO
	"_FFR_SENDER_MACRO",
#endif /* _FFR_SENDER_MACRO */

#ifdef _FFR_SOCKETDB
	"_FFR_SOCKETDB",
#endif /* _FFR_SOCKETDB */

#if _FFR_STATS
	"_FFR_STATS",
#endif /* _FFR_STATS */

#if _FFR_STATSEXT
	"_FFR_STATSEXT",
#endif /* _FFR_STATSEXT */

#if _FFR_VBR
	"_FFR_VBR",
#endif /* _FFR_VBR */

	NULL
};

/* struct dkimf_dstring -- a dynamically-sized string */
struct dkimf_dstring
{
	int			ds_alloc;
	int			ds_max;
	int			ds_len;
	u_char *		ds_buf;
};

/* base64 alphabet */
static unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
**  DKIMF_ISBLANK -- return TRUE iff a string contains only whitespace
**  
**  Parameters:
**  	str -- string to check
**
**  Return value:
**  	TRUE if "str" is either zero-length or contains only whitespace
*/

_Bool
dkimf_isblank(char *str)
{
	char *p;

	for (p = str; *p != '\0'; p++)
	{
		if (isascii(*p) && isspace(*p))
			continue;

		return FALSE;
	}

	return TRUE;
}

/*
**  DKIMF_OPTLIST -- print active FFRs
**
**  Parameters:
**  	where -- where to write the list
**
**  Return value:
**   	None.
*/

void
dkimf_optlist(FILE *where)
{
	_Bool first = TRUE;
	int c;

	assert(where != NULL);

	for (c = 0; optlist[c] != NULL; c++)
	{
		if (first)
		{
			fprintf(where, "\tActive code options:\n");
			first = FALSE;
		}

		fprintf(where, "\t\t%s\n", optlist[c]);
	}
        fprintf(where, "\t%s\n", LIBOPENDKIM_FEATURE_STRING);
}

/*
**  DKIMF_SETMAXFD -- increase the file descriptor limit as much as possible
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
dkimf_setmaxfd(void)
{
	struct rlimit rlp;

	if (getrlimit(RLIMIT_NOFILE, &rlp) != 0)
	{
		syslog(LOG_WARNING, "getrlimit(): %s", strerror(errno));
	}
	else
	{
		rlp.rlim_cur = rlp.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rlp) != 0)
		{
			syslog(LOG_WARNING, "setrlimit(): %s",
			       strerror(errno));
		}
	}
}

/*
**  DKIMF_STRIPBRACKETS -- remove angle brackets from the sender address
**
**  Parameters:
** 	addr -- address to be processed
**
**  Return value:
**  	None.
*/

void
dkimf_stripbrackets(char *addr)
{
	char *p, *q;

	assert(addr != NULL);

	p = addr;
	q = addr + strlen(addr) - 1;

	while (*p == '<' && *q == '>')
	{
		p++;
		*q-- = '\0';
	}

	if (p != addr)
	{
		for (q = addr; *p != '\0'; p++, q++)
			*q = *p;
		*q = '\0';
	}
}

/*
**  DKIMF_LOWERCASE -- lowercase-ize a string
**
**  Parameters:
**  	str -- string to convert
**
**  Return value:
**  	None.
*/

void
dkimf_lowercase(u_char *str)
{
	u_char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (isascii(*p) && isupper(*p))
			*p = tolower(*p);
	}
}

/*
**  DKIMF_CHECKHOST -- check the peerlist for a host and its wildcards
**
**  Parameters:
**  	db -- DB of records to check
**  	host -- hostname to find
**
**  Return value:
**  	TRUE if there's a match, FALSE otherwise.
*/

_Bool
dkimf_checkhost(DKIMF_DB db, char *host)
{
	_Bool exists;
	int status;
	char *p;
	char buf[BUFRSZ + 1];

	assert(host != NULL);

	/* short circuits */
	if (db == NULL || host[0] == '\0')
		return FALSE;

	/* iterate over the possibilities */
	for (p = host; p != NULL; p = strchr(p + 1, '.'))
	{
		/* try the negative case */
		snprintf(buf, sizeof buf, "!%s", p);
		exists = FALSE;
		status = dkimf_db_get(db, buf, 0, NULL, 0, &exists);
		if (status != 0)
			return FALSE;
		else if (exists)
			return FALSE;

		/* ...and now the positive case */
		exists = FALSE;
		status = dkimf_db_get(db, &buf[1], 0, NULL, 0, &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return TRUE;
	}

	return FALSE;
}

/*
**  DKIMF_CHECKIP -- check a peerlist table for an IP address or its matching
**                 wildcards
**
**  Parameters:
**  	db -- db to check
**  	ip -- IP address to find
**
**  Return value:
**  	TRUE if there's a match, FALSE otherwise.
*/

_Bool
dkimf_checkip(DKIMF_DB db, struct sockaddr *ip)
{
	_Bool exists;
	char ipbuf[DKIM_MAXHOSTNAMELEN + 1];

	assert(ip != NULL);

	/* short circuit */
	if (db == NULL)
		return FALSE;

#if AF_INET6
	if (ip->sa_family == AF_INET6)
	{
		int status;
		int bits;
		size_t dst_len;
		size_t iplen;
		char *dst;
		struct sockaddr_in6 sin6;
		struct in6_addr addr;

		memcpy(&sin6, ip, sizeof sin6);

		memcpy(&addr, &sin6.sin6_addr, sizeof addr);

		memset(ipbuf, '\0', sizeof ipbuf);
		ipbuf[0] = '!';

		dst = &ipbuf[1];
		dst_len = sizeof ipbuf - 1;

		inet_ntop(AF_INET6, &addr, dst, dst_len);
		dkimf_lowercase((u_char *) dst);
		iplen = strlen(dst);

		exists = FALSE;

		status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return FALSE;

		status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0,
		                      &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return TRUE;

		/* try it with square brackets */
		memmove(&ipbuf[2], &ipbuf[1], iplen + 1);
		ipbuf[1] = '[';
		ipbuf[iplen + 2] = ']';

		status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return FALSE;

		status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0,
		                      &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return TRUE;

		/* iterate over possible bitwise expressions */
		for (bits = 0; bits <= 128; bits++)
		{
			size_t sz;

			/* try this one */
			memset(ipbuf, '\0', sizeof ipbuf);
			ipbuf[0] = '!';

			dst = &ipbuf[1];
			dst_len = sizeof ipbuf - 1;

			inet_ntop(AF_INET6, &addr, dst, dst_len);
			dkimf_lowercase((u_char *) dst);
			iplen = strlen(dst);

			sz = strlcat(ipbuf, "/", sizeof ipbuf);
			if (sz >= sizeof ipbuf)
				return FALSE;

			dst = &ipbuf[sz];
			dst_len = sizeof ipbuf - sz;

			sz = snprintf(dst, dst_len, "%d", 128 - bits);
			if (sz >= sizeof ipbuf)
				return FALSE;

			exists = FALSE;

			status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
			if (status != 0)
				return FALSE;
			else if (exists)
				return FALSE;

			status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0,
			                      &exists);
			if (status != 0)
				return FALSE;
			else if (exists)
				return TRUE;

			/* try it with square brackets */
			memmove(&ipbuf[2], &ipbuf[1], iplen + 1);
			ipbuf[1] = '[';
			ipbuf[iplen + 2] = ']';
			ipbuf[iplen + 3] = '\0';

			sz = strlcat(ipbuf, "/", sizeof ipbuf);
			if (sz >= sizeof ipbuf)
				return FALSE;

			dst = &ipbuf[sz];
			dst_len = sizeof ipbuf - sz;

			sz = snprintf(dst, dst_len, "%d", 128 - bits);
			if (sz >= sizeof ipbuf)
				return FALSE;

			exists = FALSE;

			status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
			if (status != 0)
				return FALSE;
			if (exists)
				return FALSE;

			status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0,
			                      &exists);
			if (status != 0)
				return FALSE;
			if (exists)
				return TRUE;

			/* flip off a bit */
			if (bits != 128)
			{
				int idx;
				int bit;

				idx = 15 - (bits / 8);
				bit = bits % 8;
				addr.s6_addr[idx] &= ~(1 << bit);
			}
		}
	}
#endif /* AF_INET6 */

	if (ip->sa_family == AF_INET)
	{
		_Bool exists;
		int c;
		int status;
		int bits;
		size_t iplen;
		struct in_addr addr;
		struct in_addr mask;
		struct sockaddr_in sin;

		memcpy(&sin, ip, sizeof sin);
		memcpy(&addr.s_addr, &sin.sin_addr, sizeof addr.s_addr);

		/* try the IP address directly */
		exists = FALSE;

		ipbuf[0] = '!';
		(void) dkimf_inet_ntoa(addr, &ipbuf[1], sizeof ipbuf - 1);
		status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return FALSE;

		status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0, &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return TRUE;

		/* try it with square brackets */
		memmove(&ipbuf[2], &ipbuf[1], strlen(&ipbuf[1]) + 1);
		ipbuf[1] = '[';
		ipbuf[strlen(ipbuf)] = ']';

		status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return FALSE;

		status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0,
		                      &exists);
		if (status != 0)
			return FALSE;
		if (exists)
			return TRUE;

		/* iterate over possible bitwise expressions */
		for (bits = 32; bits >= 0; bits--)
		{
			if (bits == 32)
			{
				mask.s_addr = 0xffffffff;
			}
			else
			{
				mask.s_addr = 0;
				for (c = 0; c < bits; c++)
					mask.s_addr |= htonl(1 << (31 - c));
			}

			addr.s_addr = addr.s_addr & mask.s_addr;

			memset(ipbuf, '\0', sizeof ipbuf);
			ipbuf[0] = '!';
			(void) dkimf_inet_ntoa(addr, &ipbuf[1],
			                       sizeof ipbuf - 1);
			iplen = strlen(&ipbuf[1]);
			c = strlen(ipbuf);
			ipbuf[c] = '/';
			c++;

			snprintf(&ipbuf[c], sizeof ipbuf - c, "%d", bits);

			exists = FALSE;
			status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
			if (status != 0)
				return FALSE;
			if (exists)
				return FALSE;

			status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0,
			                      &exists);
			if (status != 0)
				return FALSE;
			if (exists)
				return TRUE;

			/* try it with square brackets */
			memmove(&ipbuf[2], &ipbuf[1], strlen(&ipbuf[1]) + 1);
			ipbuf[1] = '[';
			ipbuf[iplen + 2] = ']';
			ipbuf[iplen + 3] = '/';
			snprintf(&ipbuf[iplen + 4], sizeof ipbuf - iplen - 4,
			         "%d", bits);

			exists = FALSE;
			status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
			if (status != 0)
				return FALSE;
			if (exists)
				return FALSE;

			status = dkimf_db_get(db, &ipbuf[1], 0, NULL, 0,
			                      &exists);
			if (status != 0)
				return FALSE;
			if (exists)
				return TRUE;
		}
	}

	return FALSE;
}

#ifdef POPAUTH
/*
**  DKIMF_INITPOPAUTH -- initialize POPAUTH stuff
**
**  Parameters:
**  	None.
**
**  Return value:
**  	0 on success, an error code on failure.  See pthread_mutex_init().
*/

int
dkimf_initpopauth(void)
{
	return pthread_mutex_init(&pop_lock, NULL);
}

/*
**  DKIMF_CHECKPOPAUTH -- check a POP before SMTP database for client
**                        authentication
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	ip -- IP address to find
**
**  Return value:
**  	TRUE iff the database could be opened and the client was verified.
**
**  Notes:
**  	- does the key contain anything meaningful, like an expiry time?
*/

_Bool
dkimf_checkpopauth(DKIMF_DB db, struct sockaddr *ip)
{
	_Bool exists;
	int status;
	struct sockaddr_in *sin;
	struct in_addr addr;
	char ipbuf[DKIM_MAXHOSTNAMELEN + 1];

	assert(ip != NULL);

	if (db == NULL)
		return FALSE;

	/* skip anything not IPv4 (for now) */
	if (ip->sa_family != AF_INET)
		return FALSE;
	else
		sin = (struct sockaddr_in *) ip;


	memcpy(&addr.s_addr, &sin->sin_addr, sizeof addr.s_addr);

	dkimf_inet_ntoa(addr, ipbuf, sizeof ipbuf);
	exists = FALSE;
	status = dkimf_db_get(db, ipbuf, 0, NULL, 0, &exists);
	return (status == 0 && exists);
}
#endif /* POPAUTH */

#ifdef _FFR_REPLACE_RULES
/*
**  DKIMF_LOAD_REPLIST -- load a list of replace patterns
**
**  Parameters:
**  	in -- input stream (must already be open)
**  	list -- list to be updated
**
**  Return value:
**  	TRUE if successful, FALSE otherwise
**
**  Side effects:
**  	Prints an error message when appropriate.
*/

_Bool
dkimf_load_replist(FILE *in, struct replace **list)
{
	int line;
	int status;
	char *p;
	struct replace *newrep;
	char rule[BUFRSZ + 1];

	assert(in != NULL);
	assert(list != NULL);

	memset(rule, '\0', sizeof rule);

	while (fgets(rule, sizeof(rule) - 1, in) != NULL)
	{
		line++;

		for (p = rule; *p != '\0'; p++)
		{
			if (*p == '\n' || *p == '#')
			{
				*p = '\0';
				break;
			}
		}

		if (dkimf_isblank(rule))
			continue;

		newrep = (struct replace *) malloc(sizeof(struct replace));
		if (newrep == NULL)
		{
			fprintf(stderr, "%s: malloc(): %s\n", progname,
			        strerror(errno));
			return FALSE;
		}

		p = strrchr(rule, '\t');
		if (p == NULL)
		{
			free(newrep);
			return FALSE;
		}

		*p = '\0';

		status = regcomp(&newrep->repl_re, rule, 0);
		if (status != 0)
		{
			fprintf(stderr, "%s: regcomp() failed\n", progname);
			free(newrep);
			return FALSE;
		}

		newrep->repl_txt = strdup(p + 1);
		if (newrep->repl_txt == NULL)
		{
			fprintf(stderr, "%s: strdup(): %s\n", progname,
			        strerror(errno));
			free(newrep);
			return FALSE;
		}

		newrep->repl_next = *list;

		*list = newrep;
	}

	return TRUE;
}

/*
**  DKIMF_FREE_REPLIST -- destroy a list of replacement information
**
**  Parameters:
**  	list -- list to destroy
**
**  Return value:
**  	None.
*/

void
dkimf_free_replist(struct replace *list)
{
	struct replace *cur;
	struct replace *next;

	assert(list != NULL);

	for (cur = list; cur != NULL; cur = next)
	{
		next = cur->repl_next;
		regfree(&cur->repl_re);
		free(cur->repl_txt);
		free(cur);
	}
}

#endif /* _FFR_REPLACE_RULES */

/*
**  DKIMF_INET_NTOA -- thread-safe inet_ntoa()
**
**  Parameters:
**  	a -- (struct in_addr) to be converted
**  	buf -- destination buffer
**  	buflen -- number of bytes at buf
**
**  Return value:
**  	Size of the resultant string.  If the result is greater than buflen,
**  	then buf does not contain the complete result.
*/

size_t
dkimf_inet_ntoa(struct in_addr a, char *buf, size_t buflen)
{
	in_addr_t addr;

	assert(buf != NULL);

	addr = ntohl(a.s_addr);

	return snprintf(buf, buflen, "%d.%d.%d.%d",
	                (addr >> 24), (addr >> 16) & 0xff,
	                (addr >> 8) & 0xff, addr & 0xff);
}

/*
**  DKIMF_TRIMSPACES -- trim trailing whitespace
**
**  Parameters:
**  	str -- string to modify
**
**  Return value:
**  	None.
*/

void
dkimf_trimspaces(u_char *str)
{
	size_t len = 0;
	u_char *p;
	u_char *last;
	u_char *firsttext = NULL;

	assert(str != NULL);

	last = NULL;

	for (p = str; *p != '\0'; p++)
	{
		len++;

		if (isascii(*p) && isspace(*p))
		{
			if (last == NULL)
			{
				last = p;
				continue;
			}
		}
		else
		{
			last = NULL;
			if (firsttext == NULL)
				firsttext = p;
		}
	}

	if (last != NULL)
		*last = '\0';

	if (firsttext != NULL && firsttext != str)
		memmove(str, firsttext, len - (firsttext - str) + 1);
}

/*
**  DKIMF_STRIPCR -- remove CRs
**
**  Parameters:
**  	str -- string to modify
**
**  Return value:
**  	None.
*/

void
dkimf_stripcr(char *str)
{
	char *p;
	char *q;

	assert(str != NULL);

	for (p = str, q = str; *p != '\0'; p++)
	{
		if (*p == '\r')
			continue;

		if (q != p)
			*q = *p;
		q++;
	}

	if (q != p)
		*q = *p;
}

/*
**  DKIMF_MKPATH -- generate a path
**
**  Parameters:
**  	path -- output buffer
**  	pathlen -- bytes available at "path"
**  	root -- root to infer; if empty, use getcwd()
**  	file -- filename to use
**
**  Return value:
**  	None.
*/

void
dkimf_mkpath(char *path, size_t pathlen, char *root, char *file)
{
	assert(path != NULL);
	assert(root != NULL);
	assert(file != NULL);

	if (file[0] == '/')				/* explicit path */
	{
		strlcpy(path, file, pathlen);
	}
	else if (root[0] == '\0')			/* no root, use cwd */
	{
		char *p;

		p = getcwd(path, pathlen);
		if (p == NULL)
			strlcpy(path, "./", pathlen);
		else
			strlcat(path, "/", pathlen);
		strlcat(path, file, pathlen);
	}
	else						/* use root */
	{
		strlcpy(path, root, pathlen);
		if (root[strlen(root) - 1] != '/')
			strlcat(path, "/", pathlen);
		strlcat(path, file, pathlen);
	}
}

/*
**  DKIMF_HOSTLIST -- see if a hostname is in a pattern of hosts/domains
**
**  Parameters:
**  	host -- hostname to compare
**   	list -- NULL-terminated char * array to search
**
**  Return value:
**  	TRUE iff either "host" was in the list or it match a domain pattern
**  	found in the list.
*/

_Bool
dkimf_hostlist(char *host, char **list)
{
	int c;
	char *p;

	assert(host != NULL);
	assert(list != NULL);

	/* walk the entire list */
	for (c = 0; list[c] != NULL; c++)
	{
		/* first try a full hostname match */
		if (strcasecmp(host, list[c]) == 0)
			return TRUE;

		/* try each domain */
		for (p = strchr(host, '.'); p != NULL; p = strchr(p + 1, '.'))
		{
			if (strcasecmp(p, list[c]) == 0)
				return TRUE;
		}
	}

	/* not found */
	return FALSE;
}

/*
**  DKIMF_DSTRING_RESIZE -- resize a dynamic string (dstring)
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle
**  	len -- number of bytes desired
**
**  Return value:
**  	TRUE iff the resize worked (or wasn't needed)
**
**  Notes:
**  	This will actually ensure that there are "len" bytes available.
**  	The caller must account for the NULL byte when requesting a
**  	specific size.
*/

static _Bool
dkimf_dstring_resize(struct dkimf_dstring *dstr, int len)
{
	int newsz;
	u_char *new;

	assert(dstr != NULL);
	assert(len > 0);

	if (dstr->ds_alloc >= len)
		return TRUE;

	/* must resize */
	for (newsz = dstr->ds_alloc * 2;
	     newsz < len;
	     newsz *= 2)
	{
		/* impose ds_max limit, if specified */
		if (dstr->ds_max > 0 && newsz > dstr->ds_max)
		{
			if (len <= dstr->ds_max)
			{
				newsz = len;
				break;
			}

			return FALSE;
		}

		/* check for overflow */
		if (newsz > INT_MAX / 2)
		{
			/* next iteration will overflow "newsz" */
			return FALSE;
		}
	}

	new = malloc(newsz);
	if (new == NULL)
		return FALSE;

	memcpy(new, dstr->ds_buf, dstr->ds_alloc);

	free(dstr->ds_buf);

	dstr->ds_alloc = newsz;
	dstr->ds_buf = new;

	return TRUE;
}

/*
**  DKIMF_DSTRING_NEW -- make a new dstring
**
**  Parameters:
**  	dkim -- DKIM handle
**  	len -- initial number of bytes
**  	maxlen -- maximum allowed length (0 == unbounded)
**
**  Return value:
**  	A DKIMF_DSTRING handle, or NULL on failure.
*/

struct dkimf_dstring *
dkimf_dstring_new(int len, int maxlen)
{
	struct dkimf_dstring *new;

	/* fail on invalid parameters */
	if ((maxlen > 0 && len > maxlen) || len == 0)
		return NULL;

	if (len < BUFRSZ)
		len = BUFRSZ;

	new = malloc(sizeof(struct dkimf_dstring));
	if (new == NULL)
		return NULL;

	new->ds_buf = malloc(len);
	if (new->ds_buf == NULL)
	{
		free(new);
		return NULL;
	}

	memset(new->ds_buf, '\0', len);
	new->ds_alloc = len;
	new->ds_len = 0;
	new->ds_max = maxlen;

	return new;
}

/*
**  DKIMF_DSTRING_FREE -- destroy an existing dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle to be destroyed
**
**  Return value:
**  	None.
*/

void
dkimf_dstring_free(struct dkimf_dstring *dstr)
{
	assert(dstr != NULL);

	free(dstr->ds_buf);
	free(dstr);
}

/*
**  DKIMF_DSTRING_COPY -- copy data into a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the copy succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkimf_dstring_copy(struct dkimf_dstring *dstr, u_char *str)
{
	int len;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str);

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dkimf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* copy */
	dstr->ds_len = strlcpy((char *) dstr->ds_buf, (char *) str,
	                       dstr->ds_alloc);

	return TRUE;
}

/*
**  DKIMF_DSTRING_CAT -- append data onto a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkimf_dstring_cat(struct dkimf_dstring *dstr, u_char *str)
{
	int len;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str) + dstr->ds_len;

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dkimf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_len = strlcat((char *) dstr->ds_buf, (char *) str,
	                       dstr->ds_alloc);

	return TRUE;
}

/*
**  DKIMF_DSTRING_CAT1 -- append one byte onto a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle to update
**  	c -- input character
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkimf_dstring_cat1(struct dkimf_dstring *dstr, int c)
{
	int len;

	assert(dstr != NULL);

	len = dstr->ds_len + 1;

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dkimf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_buf[dstr->ds_len++] = c;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  DKIMF_DSTRING_CATN -- append 'n' bytes onto a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle to update
**  	str -- input string
**  	nbytes -- number of bytes to append
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkimf_dstring_catn(struct dkimf_dstring *dstr, unsigned char *str,
                   size_t nbytes)
{
	size_t needed;

	assert(dstr != NULL);
	assert(str != NULL);

	needed = dstr->ds_len + nbytes;

	/* too big? */
	if (dstr->ds_max > 0 && needed >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= needed)
	{
		/* nope; try to resize */
		if (!dkimf_dstring_resize(dstr, needed + 1))
			return FALSE;
	}

	/* append */
	memcpy(dstr->ds_buf + dstr->ds_len, str, nbytes);
	dstr->ds_len += nbytes;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  DKIMF_DSTRING_GET -- retrieve data in a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle whose string should be retrieved
**
**  Return value:
**  	Pointer to the NULL-terminated contents of "dstr".
*/

u_char *
dkimf_dstring_get(struct dkimf_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_buf;
}

/*
**  DKIMF_DSTRING_LEN -- retrieve length of data in a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle whose string should be retrieved
**
**  Return value:
**  	Number of bytes in a dstring.
*/

int
dkimf_dstring_len(struct dkimf_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_len;
}

/*
**  DKIMF_DSTRING_BLANK -- clear out the contents of a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle whose string should be cleared
**
**  Return value:
**  	None.
*/

void
dkimf_dstring_blank(struct dkimf_dstring *dstr)
{
	assert(dstr != NULL);

	dstr->ds_len = 0;
	dstr->ds_buf[0] = '\0';
}

/*
**  DKIMF_DSTRING_CHOP -- truncate contents of a dstring
**
**  Parameters:
**  	dstr -- DKIMF_DSTRING handle whose string should be cleared
**  	len -- length after which to clobber
**
**  Return value:
**  	None.
*/

void
dkimf_dstring_chop(struct dkimf_dstring *dstr, int len)
{
	assert(dstr != NULL);

	if (len < dstr->ds_len)
	{
		dstr->ds_len = len;
		dstr->ds_buf[len] = '\0';
	}
}

/*
**  DKIMF_DSTRING_PRINTF -- write variable length formatted output to a dstring
**
**  Parameters:
**  	dstr -- DKIMF_STRING handle to be updated
**  	fmt -- format
**  	... -- variable arguments
**
**  Return value:
**  	New size, or -1 on error.
*/

size_t
dkimf_dstring_printf(struct dkimf_dstring *dstr, char *fmt, ...)
{
	size_t len;
	size_t rem;
	va_list ap;
	va_list ap2;

	assert(dstr != NULL);
	assert(fmt != NULL);

	va_start(ap, fmt);
	va_copy(ap2, ap);
	rem = dstr->ds_alloc - dstr->ds_len;
	len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem, fmt, ap);
	va_end(ap);

	if (len > rem)
	{
		if (!dkimf_dstring_resize(dstr, dstr->ds_len + len + 1))
		{
			va_end(ap2);
			return (size_t) -1;
		}

		rem = dstr->ds_alloc - dstr->ds_len;
		len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem,
		                fmt, ap2);
	}

	va_end(ap2);

	dstr->ds_len += len;

	return dstr->ds_len;
}

/*
**  DKIMF_SOCKET_CLEANUP -- try to clean up the socket
**
**  Parameters:
**  	sockspec -- socket specification
**
**  Return value:
**  	0 -- nothing to cleanup or cleanup successful
**  	other -- an error code (a la errno)
*/

int
dkimf_socket_cleanup(char *sockspec)
{
	int s;
	char *colon;
	struct sockaddr_un sock;

	assert(sockspec != NULL);

	/* we only care about "local" or "unix" sockets */
	colon = strchr(sockspec, ':');
	if (colon != NULL)
	{
		if (strncasecmp(sockspec, "local:", 6) != 0 &&
		    strncasecmp(sockspec, "unix:", 5) != 0)
			return 0;
	}

	/* find the filename */
	if (colon == NULL)
	{
		colon = sockspec;
	}
	else
	{
		if (*(colon + 1) == '\0')
			return EINVAL;
	}

	/* get a socket */
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s == -1)
		return errno;

	/* set up a connection */
	memset(&sock, '\0', sizeof sock);
#ifdef BSD
	sock.sun_len = sizeof sock;
#endif /* BSD */
	sock.sun_family = PF_UNIX;
	strlcpy(sock.sun_path, colon + 1, sizeof sock.sun_path);

	/* try to connect */
	if (connect(s, (struct sockaddr *) &sock, (socklen_t) sizeof sock) != 0)
	{
		/* if ECONNREFUSED, try to unlink */
		if (errno == ECONNREFUSED)
		{
			close(s);

			if (unlink(sock.sun_path) == 0)
				return 0;
			else
				return errno;
		}

		/* if ENOENT, the socket's not there */
		else if (errno == ENOENT)
		{
			close(s);

			return 0;
		}

		/* something else happened */
		else
		{
			int saveerr;

			saveerr = errno;

			close(s);

			return saveerr;
		}
	}

	/* connection apparently succeeded */
	close(s);
	return EADDRINUSE;
}

/*
**  DKIMF_MKREGEXP -- make a regexp string from a glob string
**
**  Parameters:
**  	src -- source string
**  	dst -- destination string
**  	dstlen -- space available at "dest"
**
**  Return value:
**  	TRUE iff "dest" was big enough (based on destlen)
*/

_Bool
dkimf_mkregexp(char *src, char *dst, size_t dstlen)
{
	char *p;
	char *q;
	char *end;

	assert(src != NULL);
	assert(dst != NULL);

	if (dstlen == 0)
		return FALSE;

	dst[0] = '^';

	end = dst + dstlen;

	for (p = src, q = dst + 1; *p != '\0' && q < end; p++)
	{
		switch (*p)
		{
		  case '*':
			*q = '.';
			q++;
			*q = '*';
			q++;
			break;

		  case '+':
			*q = '\\';
			q++;
			*q = '+';
			q++;
			break;

		  case '.':
			*q = '\\';
			q++;
			*q = '.';
			q++;
			break;

		  default:
			*q = *p;
			q++;
			break;
		}
	}

	*q++ = '$';

	if (q >= end)
		return FALSE;
	else
		return TRUE;
}

/*
**  DKIMF_BASE64_ENCODE_FILE -- base64-encode a file
**
**  Parameters:
**  	infd -- input file descriptor
**  	out -- output stream
**  	lm -- left margin
** 	rm -- right margin
**  	initial -- space consumed on the initial line
**
**  Return value:
**  	None (yet).
*/

void
dkimf_base64_encode_file(infd, out, lm, rm, initial)
	int infd;
	FILE *out;
	int lm;
	int rm;
	int initial;
{
	int len;
	int bits;
	int c;
	int d;
	int char_count;
	ssize_t rlen;
	char buf[MAXBUFRSZ];

	assert(infd >= 0);
	assert(out != NULL);
	assert(lm >= 0);
	assert(rm >= 0);
	assert(initial >= 0);

	bits = 0;
	char_count = 0;
	len = initial;

	(void) lseek(infd, 0, SEEK_SET);

	for (;;)
	{
		rlen = read(infd, buf, sizeof buf);
		if (rlen == -1)
			break;

		for (c = 0; c < rlen; c++)
		{
			bits += buf[c];
			char_count++;
			if (char_count == 3)
			{
				fputc(alphabet[bits >> 18], out);
				fputc(alphabet[(bits >> 12) & 0x3f], out);
				fputc(alphabet[(bits >> 6) & 0x3f], out);
				fputc(alphabet[bits & 0x3f], out);
				len += 4;
				if (rm > 0 && lm > 0 && len >= rm - 4)
				{
					fputc('\n', out);
					for (d = 0; d < lm; d++)
						fputc(' ', out);
					len = lm;
				}
				bits = 0;
				char_count = 0;
			}
			else
			{
				bits <<= 8;
			}
		}

		if (rlen < (ssize_t) sizeof buf)
			break;
	}

	if (char_count != 0)
	{
		if (rm > 0 && lm > 0 && len >= rm - 4)
		{
			fputc('\n', out);
			for (d = 0; d < lm; d++)
				fputc(' ', out);
		}
		bits <<= 16 - (8 * char_count);
		fputc(alphabet[bits >> 18], out);
		fputc(alphabet[(bits >> 12) & 0x3f], out);
		if (char_count == 1)
			fputc('=', out);
		else
			fputc(alphabet[(bits >> 6) & 0x3f], out);
		fputc('=', out);
	}
}

/*
**  DKIMF_SUBDOMAIN -- determine whether or not one domain is a subdomain
**                     of the other
**
**  Parameters:
**  	d1 -- candidate domain
**  	d2 -- possible superdomain
**
**  Return value:
**  	TRUE iff d1 is a subdomain of d2.
*/

_Bool
dkimf_subdomain(char *d1, char *d2)
{
	char *p;

	assert(d1 != NULL);
	assert(d2 != NULL);

#if 0
	if (strcasecmp(d1, d2) == 0)
		return TRUE;
#endif /* 0 */

	for (p = strchr(d1, '.'); p != NULL; p = strchr(p + 1, '.'))
	{
		if (strcasecmp(d2, p + 1) == 0)
			return TRUE;
	}

	return FALSE;
}

/*
**  DKIMF_IPSTRING -- convert an IP address to a string
**
**  Parameters:
**  	buf -- target buffer
**  	buflen -- bytes available at "buf"
**  	ss -- socket description
**
**  Return value:
**  	None.
*/

void
dkimf_ipstring(char *buf, size_t buflen, struct sockaddr_storage *ss)
{
	assert(buf != NULL);
	assert(ss != NULL);

	switch (ss->ss_family)
	{
	  case AF_INET:
	  {
		struct sockaddr_in *sa;

		sa = (struct sockaddr_in *) ss;

		(void) inet_ntop(ss->ss_family, &sa->sin_addr, buf, buflen);

		break;
	  }

#ifdef AF_INET6
	  case AF_INET6:
	  {
		struct sockaddr_in6 *sa;

		sa = (struct sockaddr_in6 *) ss;

		(void) inet_ntop(ss->ss_family, &sa->sin6_addr, buf, buflen);

		break;
	  }
#endif /* AF_INET6 */

	  default:
		break;
	}
}

#ifdef USE_UNBOUND
/*
**  DKIMF_TIMESPEC_PAST -- return TRUE iff the time described by a timespec
**                         structure has passed
**
**  Parameters:
**  	ts -- timespec structure to evaluate
**
**  Return value:
**  	TRUE if "tv" refers to a time in the past, false otherwise.
*/

_Bool
dkimf_timespec_past(struct timespec *ts)
{
	struct timeval now;

	assert(ts != NULL);

	(void) gettimeofday(&now, NULL);

	if (now.tv_sec > ts->tv_sec ||
	    (now.tv_sec == ts->tv_sec && now.tv_usec * 1000 > ts->tv_nsec))
		return TRUE;
	else
		return FALSE;
}

/*
**  DKIMF_WAIT_FD -- wait for a descriptor to become read-ready
**
**  Parameters:
**  	fd -- descriptor of interest
**  	until -- maximum wait time
**
**  Return value:
**  	1 -- descriptor is ready
**  	0 -- timeout
**  	-1 -- error
*/

int
dkimf_wait_fd(int fd, struct timespec *until)
{
	fd_set fds;
	struct timeval now;
	struct timeval left;

	assert(fd >= 0);

	(void) gettimeofday(&now, NULL);

	if (until != NULL)
	{
		if (until->tv_sec < now.tv_sec ||
		    (until->tv_sec == now.tv_sec &&
		     until->tv_nsec < now.tv_usec * 1000))
		{
			left.tv_sec = 0;
			left.tv_usec = 0;
		}
		else
		{
			left.tv_sec = until->tv_sec - now.tv_sec;
			left.tv_usec = until->tv_nsec / 1000 - now.tv_usec;

			if (until->tv_nsec / 1000 < now.tv_usec)
			{
				left.tv_usec += 1000000;
				left.tv_sec--;
			}
		}
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	return select(fd + 1, &fds, NULL, NULL, until == NULL ? NULL : &left);
}
#endif /* USE_UNBOUND */
