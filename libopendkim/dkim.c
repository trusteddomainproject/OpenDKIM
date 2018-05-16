/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2015, 2018, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! REENTRANT */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <netdb.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#ifndef USE_GNUTLS
# include <pthread.h>
#endif /* ! USE_GNUTLS */
#include <resolv.h>
#ifdef USE_TRE
# ifdef TRE_PRE_080
#  include <tre/regex.h>
#  define tre_regcomp	regcomp
#  define tre_regexec	regexec
#  define tre_regaexec	regaexec
#  define tre_regfree	regfree
#  define tre_regerror	regerror
# else /* TRE_PRE_080 */
#  include <tre/tre.h>
#  ifndef TRE_USE_SYSTEM_REGEX_H
#   define regcomp	tre_regcomp
#   define regexec	tre_regexec
#   define regfree	tre_regfree
#   define regerror	tre_regerror
#  endif /* TRE_USE_SYSTEM_REGEX_H */
# endif /* TRE_PRE_080 */
#else /* USE_TRE */
# include <regex.h>
#endif /* USE_TRE */

#ifdef __STDC__
# include <stdarg.h>
#else /* __STDC__ */
# include <varargs.h>
#endif /* _STDC_ */

#ifdef USE_GNUTLS
/* GnuTLS includes */
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
# include <gnutls/abstract.h>
# include <gnutls/x509.h>
#else /* USE_GNUTLS */
/* OpenSSL includes */
# include <openssl/opensslv.h>
# include <openssl/pem.h>
# include <openssl/rsa.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/sha.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-types.h"
#include "dkim-tables.h"
#include "dkim-keys.h"
#include "dkim-report.h"
#include "dkim-util.h"
#include "dkim-canon.h"
#include "dkim-dns.h"
#ifdef QUERY_CACHE
# include "dkim-cache.h"
#endif /* QUERY_CACHE */
#include "util.h"
#include "base64.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* prototypes */
void dkim_error __P((DKIM *, const char *, ...));

/* macros */
#define	DKIM_STATE_INIT		0
#define	DKIM_STATE_HEADER	1
#define	DKIM_STATE_EOH1		2
#define	DKIM_STATE_EOH2		3
#define	DKIM_STATE_BODY		4
#define	DKIM_STATE_EOM1		5
#define	DKIM_STATE_EOM2		6
#define	DKIM_STATE_UNUSABLE	99

#define	DKIM_CHUNKSTATE_INIT	0
#define	DKIM_CHUNKSTATE_HEADER	1
#define	DKIM_CHUNKSTATE_BODY	2
#define	DKIM_CHUNKSTATE_DONE	3

#define	DKIM_CRLF_UNKNOWN	(-1)
#define	DKIM_CRLF_LF		0
#define	DKIM_CRLF_CRLF		1

#define	DKIM_PHASH(x)		((x) - 32)

#ifdef _FFR_DIFFHEADERS
# define COST_INSERT		1
# define COST_DELETE		1
# define COST_SUBST		2
#endif /* _FFR_DIFFHEADERS */

#define	BUFRSZ			1024
#define	CRLF			"\r\n"
#define	SP			" "

#define	DEFCLOCKDRIFT		300
#define	DEFMINKEYBITS		1024
#define	DEFTIMEOUT		10
#define	MINSIGLEN		8

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

#ifndef T_AAAA
# define T_AAAA			28
#endif /* ! T_AAAA */

/* need fast strtoul() and strtoull()? */
#ifdef NEED_FAST_STRTOUL
# define strtoul(x,y,z)		dkim_strtoul((x), (y), (z))
# define strtoull(x,y,z)	dkim_strtoull((x), (y), (z))
#endif /* NEED_FAST_STRTOUL */

#define	CLOBBER(x)	if ((x) != NULL) \
			{ \
				dkim_mfree(dkim->dkim_libhandle, dkim->dkim_closure, (x)); \
				(x) = NULL; \
			}

#define	HCLOBBER(x)	if ((x) != NULL) \
			{ \
				free((x)); \
				(x) = NULL; \
			}

# define DSTRING_CLOBBER(x) if ((x) != NULL) \
			{ \
				dkim_dstring_free((x)); \
				(x) = NULL; \
			}

#ifdef USE_GNUTLS
# define KEY_CLOBBER(x)	if ((x) != NULL) \
			{ \
				gnutls_x509_privkey_deinit((x)); \
				(x) = NULL; \
			}

# define PUBKEY_CLOBBER(x)	if ((x) != NULL) \
			{ \
				gnutls_pubkey_deinit((x)); \
				(x) = NULL; \
			}

# define PRIVKEY_CLOBBER(x)	if ((x) != NULL) \
			{ \
				gnutls_privkey_deinit((x)); \
				(x) = NULL; \
			}

#else /* USE_GNUTLS */
# define BIO_CLOBBER(x)	if ((x) != NULL) \
			{ \
				BIO_free((x)); \
				(x) = NULL; \
			}

# define RSA_CLOBBER(x)	if ((x) != NULL) \
			{ \
				RSA_free((x)); \
				(x) = NULL; \
			}

# define EVP_CLOBBER(x)	if ((x) != NULL) \
			{ \
				EVP_PKEY_free((x)); \
				(x) = NULL; \
			}
#endif /* ! USE_GNUTLS */

/* macros */
#define DKIM_ISLWSP(x)  ((x) == 011 || (x) == 013 || (x) == 014 || (x) == 040)

/* recommended list of headers to sign, from RFC6376 Section 5.4 */
const u_char *dkim_should_signhdrs[] =
{
	"from",
	"reply-to",
	"subject",
	"date",
	"to",
	"cc",
	"resent-date",
	"resent-from",
	"resent-sender",
	"resent-to",
	"resent-cc",
	"in-reply-to",
	"references",
	"list-id",
	"list-help",
	"list-unsubscribe",
	"list-subscribe",
	"list-post",
	"list-owner",
	"list-archive",
	NULL
};

/* recommended list of headers not to sign, from RFC6376 Section 5.4 */
const u_char *dkim_should_not_signhdrs[] =
{
	"return-path",
	"received",
	"comments",
	"keywords",
	NULL
};

/* required list of headers to sign */
const u_char *dkim_required_signhdrs[] =
{
	"from",
	NULL
};

/* ========================= PRIVATE SECTION ========================= */

/*
**  DKIM_SET_FREE -- destroy a DKIM_SET 
**
**  Parameters:
**  	dkim -- DKIM context
**  	set  -- the set to destroy
**
**  Return value:
**  	None
*/

static void
dkim_set_free(DKIM *dkim, DKIM_SET *set)
{
	int c;
	DKIM_PLIST *plist;
	DKIM_PLIST *pnext;

	assert(set != NULL);

	for (c = 0; c < NPRINTABLE; c++)
	{
		for (plist = set->set_plist[c]; plist != NULL; plist = pnext)
		{
			pnext = plist->plist_next;

			CLOBBER(plist);
		}
	}

	CLOBBER(set->set_data);
	CLOBBER(set);
}

/*
**  DKIM_SET_FIRST -- return first set in a context
**
**  Parameters:
**  	dkim -- DKIM context
**  	type -- type to find, or DKIM_SETTYPE_ANY
**
**  Return value:
**  	Pointer to the first DKIM_SET in the context, or NULL if none.
*/

static DKIM_SET *
dkim_set_first(DKIM *dkim, dkim_set_t type)
{
	DKIM_SET *set;

	assert(dkim != NULL);

	if (type == DKIM_SETTYPE_ANY)
		return dkim->dkim_sethead;

	for (set = dkim->dkim_sethead; set != NULL; set = set->set_next)
	{
		if (set->set_type == type)
			return set;
	}

	return NULL;
}

/*
**  DKIM_SET_NEXT -- return next set in a context
**
**  Parameters:
**  	set -- last set reported (i.e. starting point for this search)
**  	type -- type to find, or DKIM_SETTYPE_ANY
**
**  Return value:
**  	Pointer to the next DKIM_SET in the context, or NULL if none.
*/

static DKIM_SET *
dkim_set_next(DKIM_SET *cur, dkim_set_t type)
{
	DKIM_SET *set;

	assert(cur != NULL);

	if (type == DKIM_SETTYPE_ANY)
		return cur->set_next;

	for (set = cur->set_next; set != NULL; set = set->set_next)
	{
		if (set->set_type == type)
			return set;
	}

	return NULL;
}

/*
**  DKIM_PARAM_GET -- get a parameter from a set
**
**  Parameters:
**  	set -- set to search
**  	param -- parameter to find
**
**  Return value:
**  	Pointer to the parameter requested, or NULL if it's not in the set.
*/

static u_char *
dkim_param_get(DKIM_SET *set, u_char *param)
{
	DKIM_PLIST *plist;

	assert(set != NULL);
	assert(param != NULL);

	for (plist = set->set_plist[DKIM_PHASH(param[0])];
	     plist != NULL;
	     plist = plist->plist_next)
	{
		if (strcmp((char *) plist->plist_param, (char *) param) == 0)
			return plist->plist_value;
	}

	return NULL;
}

/*
**  DKIM_ADD_PLIST -- add an entry to a parameter-value set
**
**  Parameters:
**  	dkim -- DKIM context in which this is performed
**  	set -- set to modify
**   	param -- parameter
**  	value -- value
**  	force -- override existing value, if any
**
**  Return value:
**  	0 on success, -1 on failure.
**
**  Notes:
**  	Data is not copied; a reference to it is stored.
*/

static int
dkim_add_plist(DKIM *dkim, DKIM_SET *set, u_char *param, u_char *value,
               _Bool force)
{
	DKIM_PLIST *plist;

	assert(dkim != NULL);
	assert(set != NULL);
	assert(param != NULL);
	assert(value != NULL);

	if (!isprint(param[0]))
	{
		dkim_error(dkim, "invalid parameter '%s'", param);
		return -1;
	}

	/* see if we have one already */
	for (plist = set->set_plist[DKIM_PHASH(param[0])];
	     plist != NULL;
	     plist = plist->plist_next)
	{
		if (strcasecmp((char *) plist->plist_param,
		               (char *) param) == 0)
			break;
	}

	/* nope; make one and connect it */
	if (plist == NULL)
	{
		int n;

		plist = (DKIM_PLIST *) DKIM_MALLOC(dkim, sizeof(DKIM_PLIST));
		if (plist == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           sizeof(DKIM_PLIST));
			return -1;
		}
		force = TRUE;
		n = DKIM_PHASH(param[0]);
		plist->plist_next = set->set_plist[n];
		set->set_plist[n] = plist;
		plist->plist_param = param;
	}

	/* set the value if "force" was set (or this was a new entry) */
	if (force)
		plist->plist_value = value;

	return 0;
}

/*
**  DKIM_PROCESS_SET -- process a parameter set, i.e. a string of the form
**                      param=value[; param=value]*
**
**  Parameters:
**  	dkim -- DKIM context in which this is performed
**  	type -- a DKIM_SETTYPE constant
**  	str -- string to be scanned
**  	len -- number of bytes available at "str"
**  	udata -- arbitrary user data (not used)
**  	syntax -- only check syntax and don't add 'set' to dkim handle set
**  	          list if TRUE
**  	name -- an optional "name" for this set
**
**  Return value:
**  	A DKIM_STAT constant.
*/

DKIM_STAT
dkim_process_set(DKIM *dkim, dkim_set_t type, u_char *str, size_t len,
                 void *udata, _Bool syntax, const char *name)
{
	_Bool spaced;
	int state;
	int status;
	u_char *p;
	u_char *param;
	u_char *value;
	u_char *hcopy;
	DKIM_SET *set;
	const char *settype;

	assert(dkim != NULL);
	assert(str != NULL);
	assert(type == DKIM_SETTYPE_SIGNATURE ||
	       type == DKIM_SETTYPE_SIGREPORT ||
	       type == DKIM_SETTYPE_KEY);

	param = NULL;
	value = NULL;
	state = 0;
	spaced = FALSE;

	hcopy = (u_char *) DKIM_MALLOC(dkim, len + 1);
	if (hcopy == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)", len + 1);
		return DKIM_STAT_INTERNAL;
	}
	strlcpy((char *) hcopy, (char *) str, len + 1);

	set = (DKIM_SET *) DKIM_MALLOC(dkim, sizeof(DKIM_SET));
	if (set == NULL)
	{
		DKIM_FREE(dkim, hcopy);
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           sizeof(DKIM_SET));
		return DKIM_STAT_INTERNAL;
	}

	set->set_type = type;
	settype = dkim_code_to_name(settypes, type);
	set->set_name = name;
#ifdef _FFR_CONDITIONAL
	set->set_minv = 1;
#endif /* _FFR_CONDITIONAL */

	if (!syntax)
	{
		if (dkim->dkim_sethead == NULL)
			dkim->dkim_sethead = set;
		else
			dkim->dkim_settail->set_next = set;

		dkim->dkim_settail = set;
	}

	set->set_next = NULL;
	memset(&set->set_plist, '\0', sizeof set->set_plist);
	set->set_data = hcopy;
	set->set_udata = udata;
	set->set_bad = FALSE;

	for (p = hcopy; *p != '\0'; p++)
	{
		if (!isascii(*p) || (!isprint(*p) && !isspace(*p)))
		{
			dkim_error(dkim,
			           "invalid character (ASCII 0x%02x at offset %d) in %s data",
			           *p, p - hcopy, settype);
			if (syntax)
				dkim_set_free(dkim, set);
			else
				set->set_bad = TRUE;
			return DKIM_STAT_SYNTAX;
		}

		switch (state)
		{
		  case 0:				/* before param */
			if (isspace(*p))
			{
				continue;
			}
#ifdef _FFR_CONDITIONAL
			else if (isalnum(*p) || *p == '!')
#else /* _FFR_CONDITIONAL */
			else if (isalnum(*p))
#endif /* _FFR_CONDITIONAL */
			{
#ifdef _FFR_CONDITIONAL
				if (*p == '!')
					set->set_minv = 2;
#endif /* _FFR_CONDITIONAL */
				param = p;
				state = 1;
			}
			else
			{
				dkim_error(dkim,
				           "syntax error in %s data (ASCII 0x%02x at offset %d)",
				           settype, *p, p - hcopy);
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}
			break;

		  case 1:				/* in param */
			if (isspace(*p))
			{
				spaced = TRUE;
			}
			else if (*p == '=')
			{
				*p = '\0';
				state = 2;
				spaced = FALSE;
			}
			else if (*p == ';' || spaced)
			{
				dkim_error(dkim,
				           "syntax error in %s data (ASCII 0x%02x at offset %d)",
				           settype, *p, p - hcopy);
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}
			break;

		  case 2:				/* before value */
			if (isspace(*p))
			{
				continue;
			}
			else if (*p == ';')		/* empty value */
			{
				*p = '\0';
				value = p;

				/* collapse the parameter */
				dkim_collapse(param);

				/* create the DKIM_PLIST entry */
				status = dkim_add_plist(dkim, set, param,
				                        value, TRUE);
				if (status == -1)
				{
					if (syntax)
						dkim_set_free(dkim, set);
					else
						set->set_bad = TRUE;
					return DKIM_STAT_INTERNAL;
				}

				/* reset */
				param = NULL;
				value = NULL;
				state = 0;
			}
			else
			{
				value = p;
				state = 3;
			}
			break;

		  case 3:				/* in value */
			if (*p == ';')
			{
				*p = '\0';

				/* collapse the parameter and value */
				dkim_collapse(param);
				dkim_collapse(value);

				/* create the DKIM_PLIST entry */
				status = dkim_add_plist(dkim, set, param,
				                        value, TRUE);
				if (status == -1)
				{
					if (syntax)
						dkim_set_free(dkim, set);
					else
						set->set_bad = TRUE;
					return DKIM_STAT_INTERNAL;
				}

				/* reset */
				param = NULL;
				value = NULL;
				state = 0;
			}
			break;

		  default:				/* shouldn't happen */
			assert(0);
		}
	}

	switch (state)
	{
	  case 0:					/* before param */
	  case 3:					/* in value */
		/* parse the data found, if any */
		if (value != NULL)
		{
			/* collapse the parameter and value */
			dkim_collapse(param);
			dkim_collapse(value);

			/* create the DKIM_PLIST entry */
			status = dkim_add_plist(dkim, set, param, value, TRUE);
			if (status == -1)
			{
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_INTERNAL;
			}
		}
		break;

	  case 2:					/* before value */
		/* create an empty DKIM_PLIST entry */
		status = dkim_add_plist(dkim, set, param, (u_char *) "", TRUE);
		if (status == -1)
		{
			if (syntax)
				dkim_set_free(dkim, set);
			else
				set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}
		break;

	  case 1:					/* after param */
		dkim_error(dkim, "tag without value at end of %s data",
		           settype);
		if (syntax)
			dkim_set_free(dkim, set);
		else
			set->set_bad = TRUE;
		return DKIM_STAT_SYNTAX;

	  default:					/* shouldn't happen */
		assert(0);
	}

	/* load up defaults, assert requirements */
	switch (set->set_type)
	{
	  case DKIM_SETTYPE_SIGREPORT:
		/* check validity of "rp" */
		value = dkim_param_get(set, (u_char *) "rp");
		if (value != NULL)
		{
			unsigned int tmp = 0;

			tmp = (unsigned int) strtoul(value, (char **) &p, 10);
			if (tmp > 100 || *p != '\0')
			{
				dkim_error(dkim,
				           "invalid parameter(s) in %s data",
				           settype);
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}
		}
		break;
		
	  case DKIM_SETTYPE_SIGNATURE:
		/* make sure required stuff is here */
		if (dkim_param_get(set, (u_char *) "s") == NULL ||
		    dkim_param_get(set, (u_char *) "h") == NULL ||
		    dkim_param_get(set, (u_char *) "d") == NULL ||
		    dkim_param_get(set, (u_char *) "b") == NULL ||
		    dkim_param_get(set, (u_char *) "v") == NULL ||
		    dkim_param_get(set, (u_char *) "a") == NULL)
		{
			dkim_error(dkim, "missing parameter(s) in %s data",
			           settype);
			if (syntax)
				dkim_set_free(dkim, set);
			else
				set->set_bad = TRUE;
			return DKIM_STAT_SYNTAX;
		}

#ifdef _FFR_CONDITIONAL
		/* confirm we have the right signature version */
		if (set->set_minv > 1)
		{
			uint64_t tmp = 0;
			char *end;
			DKIM_PLIST *plist;

			value = dkim_param_get(set, (u_char *) "v");
			errno = 0;

			tmp = strtoull((char *) value, &end, 10);

			if (tmp == 0 || errno != 0 || *end != '\0')
			{
				dkim_error(dkim,
				           "invalid \"v\" value in %s data",
				           settype);
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}

			if (tmp < set->set_minv)
			{
				dkim_error(dkim,
				           "version %s %s too low for parameters used",
				           value, settype);
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}

			/* ensure all mandatory tags are supported */
			for (plist = set->set_plist[DKIM_PHASH('!')];
			     plist != NULL;
			     plist = plist->plist_next)
			{
				if (dkim_name_to_code(mandatory,
				                      plist->plist_param) == -1)
				{
					dkim_error(dkim,
					           "unsupported mandatory tag %s",
					           plist->plist_param);
					if (syntax)
						dkim_set_free(dkim, set);
					else
						set->set_bad = TRUE;
					return DKIM_STAT_CANTVRFY;
				}
			}
		}

		value = dkim_param_get(set, (u_char *) "!cd");
		if (value != NULL)
		{
			char *d;
		
			d = dkim_param_get(set, (u_char *) "d");

			if (strcasecmp(value, d) == 0)
			{
				dkim_error(dkim,
				           "conditional signature is self-referencing");
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}
		}
#endif /* _FFR_CONDITIONAL */
		
		/* test validity of "t" and "x" */
		value = dkim_param_get(set, (u_char *) "t");
		if (value != NULL)
		{
			uint64_t tmp = 0;
			char *end;

			errno = 0;

			if (value[0] == '-')
			{
				errno = ERANGE;
				tmp = (uint64_t) -1;
			}
			else if (value[0] == '\0')
			{
				errno = EINVAL;
				tmp = (uint64_t) -1;
			}
			else
			{
				tmp = strtoull((char *) value, &end, 10);
			}

			if (tmp == (uint64_t) -1 || errno != 0 ||
			    *end != '\0')
			{
				dkim_error(dkim,
				           "invalid \"t\" value in %s data",
				           settype);
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}
		}

		value = dkim_param_get(set, (u_char *) "x");
		if (value != NULL)
		{
			uint64_t tmp = 0;
			char *end;

			errno = 0;

			if (value[0] == '-')
			{
				errno = ERANGE;
				tmp = (uint64_t) -1;
			}
			else if (value[0] == '\0')
			{
				errno = EINVAL;
				tmp = (uint64_t) -1;
			}
			else
			{
				tmp = strtoull((char *) value, &end, 10);
			}

			if (tmp == (uint64_t) -1 || errno != 0 ||
			    *end != '\0')
			{
				dkim_error(dkim,
				           "invalid \"x\" value in %s data",
				           settype);
				if (syntax)
					dkim_set_free(dkim, set);
				else
					set->set_bad = TRUE;
				return DKIM_STAT_SYNTAX;
			}
		}

		if (syntax)
		{
			dkim_set_free(dkim, set);
			return DKIM_STAT_OK;
		}

		/* default for "c" */
		status = dkim_add_plist(dkim, set, (u_char *) "c",
		                        (u_char *) "simple/simple",
		                        FALSE);
		if (status == -1)
		{
			set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}

		/* default for "q" */
		status = dkim_add_plist(dkim, set, (u_char *) "q",
		                        (u_char *) "dns/txt", FALSE);
		if (status == -1)
		{
			set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}

  		break;

	  case DKIM_SETTYPE_KEY:
		if (syntax)
		{
			dkim_set_free(dkim, set);
			return DKIM_STAT_OK;
		}

		status = dkim_add_plist(dkim, set, (u_char *) "k",
		                        (u_char *) "rsa", FALSE);
		if (status == -1)
		{
			set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}

		break;
			
	  default:
		assert(0);
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_LOAD_SSL_ERRORS -- suck out any OpenSSL errors queued in the thread
**                          and attach them to the DKIM handle
**
**  Parameters:
**  	dkim -- DKIM handle to update
**  	status -- status code (not used for OpenSSL)
**
**  Return value:
**  	None.
*/

static void
dkim_load_ssl_errors(DKIM *dkim, int status)
{
	assert(dkim != NULL);

	if (dkim->dkim_sslerrbuf == NULL)
	{
		dkim->dkim_sslerrbuf = dkim_dstring_new(dkim, BUFRSZ,
		                                        MAXBUFRSZ);
	}

#ifdef USE_GNUTLS

	if (dkim->dkim_sslerrbuf != NULL)
	{
		if (dkim_dstring_len(dkim->dkim_sslerrbuf) > 0)
			dkim_dstring_cat(dkim->dkim_sslerrbuf, "; ");

		dkim_dstring_cat(dkim->dkim_sslerrbuf,
		                 (char *) gnutls_strerror(status));
	}

#else /* USE_GNUTLS */

	/* log any queued SSL error messages */
	if (dkim->dkim_sslerrbuf != NULL && ERR_peek_error() != 0)
	{
		int n;
		int saveerr;
		u_long e;
		char tmp[BUFRSZ + 1];

		saveerr = errno;

		for (n = 0; ; n++)
		{
			e = ERR_get_error();
			if (e == 0)
				break;

			memset(tmp, '\0', sizeof tmp);
			(void) ERR_error_string_n(e, tmp, sizeof tmp);
			if (n != 0)
			{
				dkim_dstring_catn(dkim->dkim_sslerrbuf,
				                  "; ", 2);
			}
			dkim_dstring_cat(dkim->dkim_sslerrbuf, tmp);
		}

		errno = saveerr;
	}
#endif /* USE_GNUTLS */
}

/*
**  DKIM_SIG_LOAD_SSL_ERRORS -- suck out any OpenSSL errors queued in the thread
**                              and attach them to the signature
**
**  Parameters:
**  	dkim -- DKIM handle in which to allocate storage
**  	sig -- signature to update
**  	status -- status code (not used for OpenSSL)
**
**  Return value:
**  	None.
*/

static void
dkim_sig_load_ssl_errors(DKIM *dkim, DKIM_SIGINFO *sig, int status)
{
	assert(dkim != NULL);
	assert(sig != NULL);

	if (sig->sig_sslerrbuf == NULL)
		sig->sig_sslerrbuf = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);

#ifdef USE_GNUTLS

	if (sig->sig_sslerrbuf != NULL)
	{
		if (dkim_dstring_len(sig->sig_sslerrbuf) > 0)
			dkim_dstring_cat(sig->sig_sslerrbuf, "; ");

		dkim_dstring_cat(sig->sig_sslerrbuf,
		                 (char *) gnutls_strerror(status));
	}

#else /* USE_GNUTLS */

	/* log any queued SSL error messages */
	if (ERR_peek_error() != 0)
	{
		int n;
		int saveerr;
		u_long e;
		char tmp[BUFRSZ + 1];

		saveerr = errno;

		for (n = 0; ; n++)
		{
			e = ERR_get_error();
			if (e == 0)
				break;

			memset(tmp, '\0', sizeof tmp);
			(void) ERR_error_string_n(e, tmp, sizeof tmp);
			if (n != 0)
			{
				dkim_dstring_catn(sig->sig_sslerrbuf,
				                  "; ", 2);
			}
			dkim_dstring_cat(sig->sig_sslerrbuf, tmp);
		}

		errno = saveerr;
	}
#endif /* ! USE_GNUTLS */
}

/*
**  DKIM_PRIVKEY_LOAD -- attempt to load a private key for later use
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_privkey_load(DKIM *dkim)
{
#ifdef USE_GNUTLS
	int status;
#endif /* USE_GNUTLS */
	struct dkim_crypto *crypto;

	assert(dkim != NULL);

	if (dkim->dkim_mode != DKIM_MODE_SIGN)
		return DKIM_STAT_INVALID;

	if (dkim->dkim_signalg != DKIM_SIGN_RSASHA1 &&
	    dkim->dkim_signalg != DKIM_SIGN_RSASHA256 &&
	    dkim->dkim_signalg != DKIM_SIGN_ED25519SHA256)
		return DKIM_STAT_INVALID;

	crypto = (struct dkim_crypto *) dkim->dkim_keydata;

	if (crypto == NULL)
	{
		crypto = DKIM_MALLOC(dkim, sizeof(struct dkim_crypto));
		if (crypto == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           sizeof(struct dkim_crypto));
			return DKIM_STAT_NORESOURCE;
		}
		memset(crypto, '\0', sizeof(struct dkim_crypto));
	}

	dkim->dkim_keydata = crypto;

#ifdef USE_GNUTLS
	crypto->crypto_keydata.data = dkim->dkim_key;
	crypto->crypto_keydata.size = dkim->dkim_keylen;
#else /* USE_GNUTLS */
	if (crypto->crypto_keydata == NULL)
	{
		crypto->crypto_keydata = BIO_new_mem_buf(dkim->dkim_key,
		                                         dkim->dkim_keylen);
		if (crypto->crypto_keydata == NULL)
		{
			dkim_error(dkim, "BIO_new_mem_buf() failed");
			return DKIM_STAT_NORESOURCE;
		}
	}
#endif /* USE_GNUTLS */

#ifdef USE_GNUTLS 
	status = gnutls_x509_privkey_init(&crypto->rsa_key);
	if (status != GNUTLS_E_SUCCESS)
	{
		dkim_load_ssl_errors(dkim, status);
		dkim_error(dkim, "gnutls_x509_privkey_init() failed");
		return DKIM_STAT_NORESOURCE;
	}

	if (strncmp((char *) dkim->dkim_key, "-----", 5) == 0)
	{						/* PEM */
		status = gnutls_x509_privkey_import(crypto->rsa_key,
		                                    &crypto->rsa_keydata,
	                                            GNUTLS_X509_FMT_PEM);
	}
	else
	{
		status = gnutls_x509_privkey_import(crypto->rsa_key,
		                                    &crypto->rsa_keydata,
	                                            GNUTLS_X509_FMT_DER);
	}

	if (status != GNUTLS_E_SUCCESS)
	{
		dkim_load_ssl_errors(dkim, status);
		dkim_error(dkim, "gnutls_x509_privkey_import() failed");
		return DKIM_STAT_NORESOURCE;
	}

	status = gnutls_privkey_init(&crypto->rsa_privkey);
	if (status != GNUTLS_E_SUCCESS)
	{
		dkim_load_ssl_errors(dkim, status);
		dkim_error(dkim, "gnutls_privkey_init() failed");
		return DKIM_STAT_NORESOURCE;
	}

	status = gnutls_privkey_import_x509(crypto->rsa_privkey,
	                                    crypto->rsa_key, 0);
	if (status != GNUTLS_E_SUCCESS)
	{
		dkim_load_ssl_errors(dkim, status);
		dkim_error(dkim, "gnutls_privkey_import_x509() failed");
		(void) gnutls_privkey_deinit(rsa->rsa_privkey);
		return DKIM_STAT_NORESOURCE;
	}

	(void) gnutls_privkey_get_pk_algorithm(rsa->rsa_privkey,
	                                       &rsa->rsa_keysize);

#else /* USE_GNUTLS */

	if (strncmp((char *) dkim->dkim_key, "-----", 5) == 0)
	{						/* PEM */
		crypto->crypto_pkey = PEM_read_bio_PrivateKey(crypto->crypto_keydata,
		                                              NULL, NULL,
		                                              NULL);

		if (crypto->crypto_pkey == NULL)
		{
			dkim_load_ssl_errors(dkim, 0);
			dkim_error(dkim, "PEM_read_bio_PrivateKey() failed");
			BIO_free(crypto->crypto_keydata);
			return DKIM_STAT_NORESOURCE;
		}
	}
	else
	{						/* DER */
		crypto->crypto_pkey = d2i_PrivateKey_bio(crypto->crypto_keydata,
		                                         NULL);

		if (crypto->crypto_pkey == NULL)
		{
			dkim_load_ssl_errors(dkim, 0);
			dkim_error(dkim, "d2i_PrivateKey_bio() failed");
			BIO_free(crypto->crypto_keydata);
			return DKIM_STAT_NORESOURCE;
		}
	}

	if (dkim->dkim_signalg == DKIM_SIGN_ED25519SHA256)
	{
		crypto->crypto_keysize = EVP_PKEY_size(crypto->crypto_pkey) * 8;
	}
	else
	{
		crypto->crypto_key = EVP_PKEY_get1_RSA(crypto->crypto_pkey);
		if (crypto->crypto_key == NULL)
		{
			dkim_load_ssl_errors(dkim, 0);
			dkim_error(dkim, "EVP_PKEY_get1_RSA() failed");
			BIO_free(crypto->crypto_keydata);
			return DKIM_STAT_NORESOURCE;
		}

		crypto->crypto_keysize = RSA_size(crypto->crypto_key) * 8;
		crypto->crypto_pad = RSA_PKCS1_PADDING;
	}

	crypto->crypto_outlen = crypto->crypto_keysize / 8;
	crypto->crypto_out = DKIM_MALLOC(dkim, crypto->crypto_outlen);
	if (crypto->crypto_out == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           crypto->crypto_keysize / 8);
		RSA_free(crypto->crypto_key);
		BIO_free(crypto->crypto_keydata);
		return DKIM_STAT_NORESOURCE;
	}
#endif /* USE_GNUTLS */

	return DKIM_STAT_OK;
}

/*
**  DKIM_CHECK_REQUIREDHDRS -- see if all requried headers are present
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	Pointer to the name of a header that's absent, or NULL if all
**  	are present.
*/

static const unsigned char *
dkim_check_requiredhdrs(DKIM *dkim)
{
	_Bool found;
	int c;
	size_t len;
	struct dkim_header *hdr;
	u_char **required_signhdrs;

	assert(dkim != NULL);

	required_signhdrs = dkim->dkim_libhandle->dkiml_requiredhdrs;
	for (c = 0; required_signhdrs[c] != NULL; c++)
	{
		found = FALSE;
		len = strlen((char *) required_signhdrs[c]);

		for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (hdr->hdr_namelen == len &&
			    strncasecmp((char *) hdr->hdr_text,
			                (char *) required_signhdrs[c],
			                len) == 0)
			{
				found = TRUE;
				break;
			}
		}

		if (!found)
			return required_signhdrs[c];
	}

	return NULL;
}

/*
**  DKIM_SET_GETUDATA -- retrieve user data associated with a set
**
**  Parameters:
**  	set -- a DKIM_SET handle
**
**  Return value:
**  	Stored opaque handle, if any; NULL otherwise.
*/

static void *
dkim_set_getudata(DKIM_SET *set)
{
	assert(set != NULL);

	return set->set_udata;
}

/*
**  DKIM_GET_HEADER -- find a header in a queue of headers
**
**  Parameters:
**  	dkim -- DKIM handle
**  	name -- name of the header to find
**  	namelen -- length of the header name at "name" (or 0)
**  	inst -- instance to find (0 == first/any)
**
**  Return value:
**  	Pointer to a (struct dkim_header), or NULL if not found.
*/

static struct dkim_header *
dkim_get_header(DKIM *dkim, u_char *name, size_t namelen, int inst)
{
	size_t len;
	struct dkim_header *hdr;

	assert(dkim != NULL);
	assert(name != NULL);

	if (namelen == 0)
		len = strlen((char *) name);
	else
		len = namelen;

	for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (hdr->hdr_namelen == len &&
		    strncasecmp((char *) hdr->hdr_text,
		                (char *) name, len) == 0)
		{
			if (inst == 0)
				return hdr;
			else
				inst--;
		}
	}

	return NULL;
}

/*
**  DKIM_KEY_SMTP -- return TRUE iff a parameter set defines an SMTP key
**
**  Parameters:
**  	set -- set to be checked
**
**  Return value:
**  	TRUE iff "set" contains an "s" parameter whose value is either
**  	"email" or "*".
*/

static _Bool
dkim_key_smtp(DKIM_SET *set)
{
	u_char *val;
	char *last;
	u_char *p;
	char buf[BUFRSZ + 1];

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_KEY);

	val = dkim_param_get(set, (u_char * ) "s");

	if (val == NULL)
		return TRUE;

	strlcpy(buf, (char *) val, sizeof buf);

	for (p = (u_char *) strtok_r(buf, ":", &last);
	     p != NULL;
	     p = (u_char *) strtok_r(NULL, ":", &last))
	{
		if (strcmp((char *) p, "*") == 0 ||
		    strcasecmp((char *) p, "email") == 0)
			return TRUE;
	}

	return FALSE;
}

/*
**  DKIM_KEY_HASHOK -- return TRUE iff a signature's hash is in the approved
**                     list of hashes for a given key
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**  	hashlist -- colon-separated approved hash list
**
**  Return value:
**  	TRUE iff a particular hash is in the approved list of hashes.
*/

static _Bool
dkim_key_hashok(DKIM_SIGINFO *sig, u_char *hashlist)
{
	int hashalg;
	u_char *x, *y;
	u_char tmp[BUFRSZ + 1];

	assert(sig != NULL);

	if (hashlist == NULL)
		return TRUE;

	x = NULL;
	memset(tmp, '\0', sizeof tmp);

	y = hashlist;
	for (;;)
	{
		if (*y == ':' || *y == '\0')
		{
			if (x != NULL)
			{
				strlcpy((char *) tmp, (char *) x, sizeof tmp);
				tmp[y - x] = '\0';
				hashalg = dkim_name_to_code(hashes,
				                            (char *) tmp);
				if (hashalg == sig->sig_hashtype)
					return TRUE;
			}

			x = NULL;
		}
		else if (x == NULL)
		{
			x = y;
		}

		if (*y == '\0')
			return FALSE;
		y++;
	}

	/* NOTREACHED */
}

/*
**  DKIM_KEY_HASHESOK -- return TRUE iff this key supports at least one
**                       hash method we know about (or doesn't specify)
**
**  Parameters:
**  	hashlist -- colon-separated list of hashes (or NULL)
**
**  Return value:
**  	TRUE iff this key supports at least one hash method we know about
**  	(or doesn't specify)
*/

static _Bool
dkim_key_hashesok(DKIM_LIB *lib, u_char *hashlist)
{
	u_char *x, *y;
	u_char tmp[BUFRSZ + 1];

	assert(lib != NULL);

	if (hashlist == NULL)
		return TRUE;

	x = NULL;
	memset(tmp, '\0', sizeof tmp);

	y = hashlist;
	for (;;)
	{
		if (*y == ':' || *y == '\0')
		{
			if (x != NULL)
			{
				int hashcode;

				strlcpy((char *) tmp, (char *) x, sizeof tmp);
				tmp[y - x] = '\0';

				hashcode = dkim_name_to_code(hashes,
				                             (char *) tmp);

				if (hashcode != -1 &&
				    (hashcode != DKIM_HASHTYPE_SHA256 ||
				     dkim_libfeature(lib, DKIM_FEATURE_SHA256)))
					return TRUE;
			}

			x = NULL;
		}
		else if (x == NULL)
		{
			x = y;
		}

		if (*y == '\0')
			return FALSE;
		y++;
	}

	/* NOTREACHED */
}

/*
**  DKIM_SIG_HDRLISTOK -- return TRUE iff a header list contained at least
**                        all of those headers which MUST be signed
**
**  Parameters:
**  	dkim -- DKIM handle
**  	hdrlist -- header list to be checked
**
**  Return value:
**  	1 if the header list meets spec requirements,
**  	0 if not,
**  	-1 on error
*/

static _Bool
dkim_sig_hdrlistok(DKIM *dkim, u_char *hdrlist)
{
	_Bool in = FALSE;
	_Bool found;
	int c;
	int d;
	int nh;
	u_char *p;
	u_char **ptrs;
	u_char **required_signhdrs;;
	u_char tmp[DKIM_MAXHEADER + 1];

	assert(dkim != NULL);
	assert(hdrlist != NULL);

	strlcpy((char *) tmp, (char *) hdrlist, sizeof tmp);

	/* figure out how many headers were named */
	c = 0;
	for (p = tmp; *p != '\0'; p++)
	{
		if (*p == ':')
		{
			in = FALSE;
		}
		else if (isascii(*p) && !isspace(*p) && !in)
		{
			c++;
			in = TRUE;
		}
	}

	nh = c;

	/* allocate an array of pointers to them */
	ptrs = DKIM_MALLOC(dkim, sizeof(u_char *) * nh);
	if (ptrs == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           sizeof(u_char *) * nh);
		return -1;
	}

	/* set the pointers */
	c = 0;
	in = FALSE;
	for (p = tmp; *p != '\0'; p++)
	{
		if (*p == ':')
		{
			*p = '\0';
			in = FALSE;
		}
		else if (isascii(*p) && !isspace(*p) && !in)
		{
			ptrs[c++] = p;
			in = TRUE;
		}
	}

	/* verify that each required header was represented */
	required_signhdrs = dkim->dkim_libhandle->dkiml_requiredhdrs;
	for (d = 0; ; d++)
	{
		if (required_signhdrs[d] == NULL)
			break;

		found = FALSE;

		for (c = 0; c < nh; c++)
		{
			if (strcasecmp((char *) required_signhdrs[d],
			               (char *) ptrs[c]) == 0)
			{
				found = TRUE;
				break;
			}
		}

		if (!found)
		{
			DKIM_FREE(dkim, ptrs);

			return 0;
		}
	}

	DKIM_FREE(dkim, ptrs);

	return 1;
}

/*
**  DKIM_SIG_DOMAINOK -- return TRUE iff a signature appears to have valid
**                       domain correlation; that is, "i" must be the same
**                       domain as or a subdomain of "d"
**
**  Parameters:
**  	dkim -- DKIM handle
**  	set -- signature set to be checked
**
**  Return value:
**  	TRUE iff the "i" parameter and the "d" parameter match up.
*/

static _Bool
dkim_sig_domainok(DKIM *dkim, DKIM_SET *set)
{
	char *at;
	char *dot;
	u_char *i;
	u_char *d;
	u_char addr[MAXADDRESS + 1];

	assert(dkim != NULL);
	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	i = dkim_param_get(set, (u_char *) "i");
	d = dkim_param_get(set, (u_char *) "d");

	assert(d != NULL);

	memset(addr, '\0', sizeof addr);

	if (i == NULL)
		snprintf((char *) addr, sizeof addr, "@%s", d);
	else
		dkim_qp_decode(i, addr, sizeof addr - 1);

	at = strchr((char *) addr, '@');
	if (at == NULL)
		return FALSE;

	if (strcasecmp(at + 1, (char *) d) == 0)
		return TRUE;

	for (dot = strchr(at, '.'); dot != NULL; dot = strchr(dot + 1, '.'))
	{
		if (strcasecmp(dot + 1, (char *) d) == 0)
		{
			dkim->dkim_subdomain = TRUE;
			return TRUE;
		}
	}

	return FALSE;
}

/*
**  DKIM_SIG_EXPIRED -- return TRUE iff a signature appears to have expired
**
**  Parameters:
**  	set -- signature set to be checked
**  	drift -- seconds of drift allowed
**
**  Return value:
**  	TRUE iff "set" contains an "x=" parameter which indicates a time
**  	which has passed.
**
**  Notes:
**  	Syntax is not checked here.  It's checked in dkim_process_set().
*/

static _Bool
dkim_sig_expired(DKIM_SET *set, uint64_t drift)
{
	time_t now;
	uint64_t expire;
	uint64_t nowl;
	u_char *val;

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	val = dkim_param_get(set, (u_char *) "x");
	if (val == NULL)
		return FALSE;

	if (sizeof(uint64_t) == sizeof(unsigned long long))
		expire = strtoull((char *) val, NULL, 10);
	else if (sizeof(uint64_t) == sizeof(unsigned long))
		expire = strtoul((char *) val, NULL, 10);
	else
		expire = (unsigned int) strtoul((char *) val, NULL, 10);

	(void) time(&now);
	nowl = (uint64_t) now;

	return (nowl >= expire + drift);
}

/*
**  DKIM_SIG_TIMESTAMPSOK -- return TRUE iff a signature appears to have
**                           both a timestamp and an expiration date and they
**                           are properly ordered
**
**  Parameters:
**  	set -- signature set to be checked
**
**  Return value:
**  	TRUE: - "set" contains both a "t=" parameter and an "x=" parameter
**  	        and the latter is greater than the former
**  	      - "set" is missing either "t=" or "x=" (or both)
**  	FALSE: otherwise
**
**  Notes:
**  	Syntax is not checked here.  It's checked in dkim_process_set().
*/

static _Bool
dkim_sig_timestampsok(DKIM_SET *set)
{
	uint64_t signtime;
	uint64_t expire;
	u_char *val;

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	val = dkim_param_get(set, (u_char *) "t");
	if (val == NULL)
		return TRUE;
	if (sizeof(uint64_t) == sizeof(unsigned long long))
		signtime = strtoull((char *) val, NULL, 10);
	else if (sizeof(uint64_t) == sizeof(unsigned long))
		signtime = strtoul((char *) val, NULL, 10);
	else
		signtime = (unsigned int) strtoul((char *) val, NULL, 10);

	val = dkim_param_get(set, (u_char *) "x");
	if (val == NULL)
		return TRUE;
	if (sizeof(uint64_t) == sizeof(unsigned long long))
		expire = strtoull((char *) val, NULL, 10);
	else if (sizeof(uint64_t) == sizeof(unsigned long))
		expire = strtoul((char *) val, NULL, 10);
	else
		expire = (unsigned int) strtoul((char *) val, NULL, 10);

	return (signtime < expire);
}

/*
**  DKIM_SIG_FUTURE -- return TRUE iff a signature appears to have been
**                     generated in the future
**
**  Parameters:
**  	set -- signature set to be checked
**  	drift -- seconds of drift allowed
**
**  Return value:
**  	TRUE iff "set" contains a "t=" parameter which indicates a time
**  	in the future.
**
**  Notes:
**  	Syntax is not checked here.  It's checked in dkim_process_set().
*/

static _Bool
dkim_sig_future(DKIM_SET *set, uint64_t drift)
{
	uint64_t signtime;
	uint64_t nowl;
	time_t now;
	u_char *val;

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	val = dkim_param_get(set, (u_char *) "t");
	if (val == NULL)
		return FALSE;

	if (sizeof(uint64_t) == sizeof(unsigned long long))
		signtime = strtoull((char *) val, NULL, 10);
	else if (sizeof(uint64_t) == sizeof(unsigned long))
		signtime = strtoul((char *) val, NULL, 10);
	else
		signtime = (unsigned int) strtoul((char *) val, NULL, 10);

	(void) time(&now);
	nowl = (uint64_t) now;

	return (nowl < signtime - drift);
}

/*
**  DKIM_SIG_VERSIONOK -- return TRUE iff a signature appears to have a version
**                        we can accept
**
**  Parameters:
**  	dkim -- DKIM handle
**  	set -- signature set to be checked
**
**  Return value:
**  	TRUE iff "set" appears to be based on a version of DKIM that is
**  	supported by this API.
*/

static _Bool
dkim_sig_versionok(DKIM *dkim, DKIM_SET *set)
{
	char *v;

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	v = (char *) dkim_param_get(set, (u_char *) "v");

	assert(v != NULL);

	/* check for DKIM_VERSION_SIG */
	if (strcmp(v, DKIM_VERSION_SIG) == 0)
		return TRUE;
#ifdef _FFR_CONDITIONAL
	if (strcmp(v, DKIM_VERSION_SIG2) == 0)
		return TRUE;
#endif /* _FFR_CONDITIONAL */

	/* check for DKIM_VERSION_SIGOLD if allowed */
	if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_ACCEPTV05) &&
	    strcmp(v, DKIM_VERSION_SIGOLD) == 0)
		return TRUE;

	return FALSE;
}

/*
**  DKIM_SIGLIST_SETUP -- create a signature list and load the elements
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_siglist_setup(DKIM *dkim)
{
	_Bool bsh;
	int c;
	int hashtype = DKIM_HASHTYPE_UNKNOWN;
	int hstatus;
	size_t b64siglen;
	size_t len;
	DKIM_STAT status;
	ssize_t signlen = (ssize_t) -1;
	uint64_t drift;
	dkim_canon_t bodycanon;
	dkim_canon_t hdrcanon;
	dkim_alg_t signalg;
	DKIM_SET *set;
	DKIM_LIB *lib;
	DKIM_CANON *hc;
	DKIM_CANON *bc;
	u_char *param;
	u_char *hdrlist;

	assert(dkim != NULL);

	lib = dkim->dkim_libhandle;
	drift = lib->dkiml_clockdrift;

	bsh = ((lib->dkiml_flags & DKIM_LIBFLAGS_BADSIGHANDLES) != 0);

	len = dkim->dkim_sigcount * sizeof(DKIM_SIGINFO *);
	dkim->dkim_siglist = DKIM_MALLOC(dkim, len);
	if (dkim->dkim_siglist == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)", len);
		return DKIM_STAT_NORESOURCE;
	}

	/* allocate the siginfo elements */
	for (c = 0; c < dkim->dkim_sigcount; c++)
	{
		dkim->dkim_siglist[c] = DKIM_MALLOC(dkim,
		                                    sizeof(DKIM_SIGINFO));
		if (dkim->dkim_siglist[c] == NULL)
		{
			int n;

			dkim_error(dkim,
			           "unable to allocate %d byte(s)",
			           sizeof(DKIM_SIGINFO));
			for (n = 0; n < c; n++)
				DKIM_FREE(dkim, dkim->dkim_siglist[n]);
			return DKIM_STAT_NORESOURCE;
		}

		memset(dkim->dkim_siglist[c], '\0', sizeof(DKIM_SIGINFO));
	}

	/* populate the elements */
	for (set = dkim_set_first(dkim, DKIM_SETTYPE_SIGNATURE), c = 0;
	     set != NULL && c < dkim->dkim_sigcount;
	     set = dkim_set_next(set, DKIM_SETTYPE_SIGNATURE), c++)
	{
		/* cope with bad ones */
		if (set->set_bad && !bsh)
		{
			c--;
			continue;
		}

		/* defaults */
		dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_UNKNOWN;
		dkim->dkim_siglist[c]->sig_dnssec_key = DKIM_DNSSEC_UNKNOWN;

		/* store the set */
		dkim->dkim_siglist[c]->sig_taglist = set;

		/* override query method? */
		if (lib->dkiml_querymethod != DKIM_QUERY_UNKNOWN)
			dkim->dkim_siglist[c]->sig_query = lib->dkiml_querymethod;

		/* critical stuff: signing domain */
		param = dkim_param_get(set, (u_char *) "d");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_D;
			continue;
		}
		else if (param[0] == '\0')
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_EMPTY_D;
			continue;
		}
		dkim->dkim_siglist[c]->sig_domain = param;

		/* critical stuff: selector */
		param = dkim_param_get(set, (u_char *) "s");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_S;
			continue;
		}
		else if (param[0] == '\0')
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_EMPTY_S;
			continue;
		}
		dkim->dkim_siglist[c]->sig_selector = param;

		/* some basic checks first */
		param = dkim_param_get(set, (u_char *) "v");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_V;
			continue;
		}
		else if (param[0] == '\0')
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_EMPTY_V;
			continue;
		}
		else if (!dkim_sig_versionok(dkim, set))
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_VERSION;
			continue;
		}
		else if (!dkim_sig_domainok(dkim, set))
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_DOMAIN;
			continue;
		}
		else if (dkim_sig_expired(set, drift))
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_EXPIRED;
			continue;
		}
		else if (dkim_sig_future(set, drift))
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_FUTURE;
			continue;
		}
		else if (!dkim_sig_timestampsok(set))
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_TIMESTAMPS;
			continue;
		}

		/* determine canonicalizations */
		param = dkim_param_get(set, (u_char *) "c");
		if (param == NULL)
		{
			hdrcanon = DKIM_CANON_SIMPLE;
			bodycanon = DKIM_CANON_SIMPLE;
		}
		else
		{
			char *q;
			char value[BUFRSZ + 1];

			strlcpy(value, (char *) param, sizeof value);

			q = strchr(value, '/');
			if (q != NULL)
				*q = '\0';

			hdrcanon = dkim_name_to_code(canonicalizations, value);
			if (hdrcanon == -1)
			{
				dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_HC;
				continue;
			}

			if (q == NULL)
			{
				bodycanon = DKIM_CANON_SIMPLE;
			}
			else
			{
				bodycanon = dkim_name_to_code(canonicalizations,
				                              q + 1);

				if (bodycanon == -1)
				{
					dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_BC;
					continue;
				}
			}
		}

		/* determine hash type */
		param = dkim_param_get(set, (u_char *) "a");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_A;
			continue;
		}
		else
		{
			signalg = dkim_name_to_code(algorithms,
			                            (char *) param);

			if (signalg == -1)
			{
				dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_A;
				continue;
			}

			switch (signalg)
			{
			  case DKIM_SIGN_RSASHA1:
				hashtype = DKIM_HASHTYPE_SHA1;
				break;

			  case DKIM_SIGN_RSASHA256:
				if (dkim_libfeature(lib, DKIM_FEATURE_SHA256))
				{
					hashtype = DKIM_HASHTYPE_SHA256;
				}
				else
				{
					dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_A;
					continue;
				}
				break;

			  case DKIM_SIGN_ED25519SHA256:
				if (dkim_libfeature(lib, DKIM_FEATURE_ED25519))
				{
					hashtype = DKIM_HASHTYPE_SHA256;
				}
				else
				{
					dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_A;
					continue;
				}
				break;

			  default:
				assert(0);
				/* NOTREACHED */
			}

			dkim->dkim_siglist[c]->sig_signalg = signalg;
			dkim->dkim_siglist[c]->sig_hashtype = hashtype;
		}

		/* determine header list */
		param = dkim_param_get(set, (u_char *) "h");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_H;
			continue;
		}
		else if (param[0] == '\0')
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_EMPTY_H;
			continue;
		}

		hstatus = dkim_sig_hdrlistok(dkim, param);
		if (hstatus == 0)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_H;
			continue;
		}
		else if (hstatus == -1)
		{
			return DKIM_STAT_NORESOURCE;
		}

		hdrlist = param;

		/* determine signing length */
		signlen = (ssize_t) -1;
		param = dkim_param_get(set, (u_char *) "l");
		if (param != NULL)
		{
			char *q;

			errno = 0;
			if (param[0] == '-')
			{
				errno = ERANGE;
				signlen = ULONG_MAX;
			}
			else
			{
				signlen = (ssize_t) strtoul((char *) param,
				                          &q, 10);
			}

			if (signlen == ULONG_MAX || errno != 0 || *q != '\0')
			{
				dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_L;
				continue;
			}
		}

		/* query method */
		param = dkim_param_get(set, (u_char *) "q");
		if (param != NULL)
		{
			_Bool bad_qo = FALSE;
			dkim_query_t q = (dkim_query_t) -1;
			u_char *p;
			char *last;
			u_char *opts;
			u_char tmp[BUFRSZ + 1];
			u_char qtype[BUFRSZ + 1];

			strlcpy((char *) qtype, (char *) param, sizeof qtype);

			for (p = (u_char *) strtok_r((char *) qtype, ":",
			                             &last);
			     p != NULL;
			     p = (u_char *) strtok_r(NULL, ":", &last))
			{
				opts = (u_char *) strchr((char *) p, '/');
				if (opts != NULL)
				{
					strlcpy((char *) tmp, (char *) p,
					        sizeof tmp);
					p = tmp;
					opts = (u_char *) strchr((char *) tmp,
					                         '/');
					if (opts != NULL)
					{
						*opts = '\0';
						opts++;
					}
				}

				/* unknown type */
				q = dkim_name_to_code(querytypes, (char *) p);
				if (q == (dkim_query_t) -1)
					continue;

				if (q == DKIM_QUERY_DNS)
				{
					/* "txt" option required */
					if (opts == NULL ||
					    strcmp((char *) opts, "txt") != 0)
					{
						bad_qo = TRUE;
						continue;
					}
				}

				break;
			}

		    	if (dkim->dkim_libhandle->dkiml_key_lookup == NULL)
			{
				if (q == (dkim_query_t) -1)
				{
					dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_Q;
					continue;
				}
				else if (bad_qo)
				{
					dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_QO;
					continue;
				}
			}

			dkim->dkim_siglist[c]->sig_query = q;
		}

		/* override query method? */
		if (lib->dkiml_querymethod != DKIM_QUERY_UNKNOWN)
			dkim->dkim_siglist[c]->sig_query = lib->dkiml_querymethod;

		/* timestamp */
		param = dkim_param_get(set, (u_char *) "t");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_timestamp = 0;
		}
		else
		{
			if (sizeof(uint64_t) == sizeof(unsigned long long))
			{
				dkim->dkim_siglist[c]->sig_timestamp = strtoull((char *) param,
				                                                NULL,
				                                                10);
			}
			else if (sizeof(uint64_t) == sizeof(unsigned long))
			{
				dkim->dkim_siglist[c]->sig_timestamp = strtoul((char *) param,
				                                               NULL,
				                                               10);
			}
			else
			{
				dkim->dkim_siglist[c]->sig_timestamp = (unsigned int) strtoul((char *) param,
				                                                              NULL,
				                                                              10);
			}
		}

		/* body hash */
		param = dkim_param_get(set, (u_char *) "bh");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_BH;
			continue;
		}
		else if (param[0] == '\0')
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_EMPTY_BH;
			continue;
		}

		/* signature */
		param = dkim_param_get(set, (u_char *) "b");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_B;
			continue;
		}
		else if (param[0] == '\0')
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_EMPTY_B;
			continue;
		}

		b64siglen = strlen((char *) param);
		dkim->dkim_siglist[c]->sig_sig = DKIM_MALLOC(dkim,
		                                             b64siglen);
		if (dkim->dkim_siglist[c]->sig_sig == NULL)
		{
			dkim_error(dkim,
			           "unable to allocate %d byte(s)",
			           b64siglen);
			return DKIM_STAT_NORESOURCE;
		}

		status = dkim_base64_decode(param,
		                            dkim->dkim_siglist[c]->sig_sig,
		                            b64siglen);
		if (status < 0)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_CORRUPT_B;
			continue;
		}
		else
		{
			dkim->dkim_siglist[c]->sig_siglen = status;
		}

		/* canonicalization handle for the headers */
		status = dkim_add_canon(dkim, TRUE, hdrcanon, hashtype,
		                        hdrlist, dkim_set_getudata(set),
		                        0, &hc);
		if (status != DKIM_STAT_OK)
			return status;
		dkim->dkim_siglist[c]->sig_hdrcanon = hc;
		dkim->dkim_siglist[c]->sig_hdrcanonalg = hdrcanon;

		/* canonicalization handle for the body */
		status = dkim_add_canon(dkim, FALSE, bodycanon,
		                        hashtype, NULL, NULL, signlen,
		                        &bc);
		if (status != DKIM_STAT_OK)
			return status;
		dkim->dkim_siglist[c]->sig_bodycanon = bc;
		dkim->dkim_siglist[c]->sig_bodycanonalg = bodycanon;

		/* the rest */
		dkim->dkim_siglist[c]->sig_bh = DKIM_SIGBH_UNTESTED;
		dkim->dkim_siglist[c]->sig_flags = 0;

		/* allow the user to generate its handle */
		if (lib->dkiml_sig_handle != NULL)
			dkim->dkim_siglist[c]->sig_context = lib->dkiml_sig_handle(dkim->dkim_closure);

		/* populate the user handle */
		if (lib->dkiml_sig_tagvalues != NULL)
		{
			u_int n;
			dkim_param_t pcode;
			struct dkim_plist *plist;
			void *user;

			user = dkim->dkim_siglist[c]->sig_context;

			for (n = 0; n < NPRINTABLE; n++)
			{
				for (plist = set->set_plist[n];
				     plist != NULL;
				     plist = plist->plist_next)
				{
					pcode = dkim_name_to_code(sigparams,
					                          (char *) plist->plist_param);

					(void) lib->dkiml_sig_tagvalues(user,
					                                pcode,
					                                plist->plist_param,
					                                plist->plist_value);
				}
			}
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_GENSIGHDR -- generate a signature header
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	dstr -- dstring to which to write
**  	delim -- delimiter
**
**  Return value:
**  	Number of bytes written to "dstr", or <= 0 on error.
*/

static size_t
dkim_gensighdr(DKIM *dkim, DKIM_SIGINFO *sig, struct dkim_dstring *dstr,
               char *delim)
{
	_Bool firsthdr;
	_Bool nosigner = FALSE;
	int n;
	int status;
	int delimlen;
	size_t hashlen;
	char *format;
	u_char *hash;
	u_char *v;
	struct dkim_header *hdr;
	u_char tmp[DKIM_MAXHEADER + 1];
	u_char b64hash[DKIM_MAXHEADER + 1];

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(dstr != NULL);
	assert(delim != NULL);

	delimlen = strlen(delim);

	/* bail if we were asked to generate an invalid signature */
	if (dkim->dkim_signer != NULL)
	{
		_Bool match = FALSE;
		u_char *sd;

		sd = strchr(dkim->dkim_signer, '@');
		if (sd == NULL)
		{
			dkim_error(dkim, "syntax error in signer value");
			return 0;
		}

		if (strcasecmp(sd + 1, sig->sig_domain) == 0)
		{
			match = TRUE;
		}
		else
		{
			for (sd = strchr(sd + 1, '.');
			     sd != NULL && !match;
			     sd = strchr(sd + 1, '.'))
			{
				if (strcasecmp(sd + 1, sig->sig_domain) == 0)
					match = TRUE;
			}
		}

		if (!match)
		{
			if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_DROPSIGNER) == 0)
			{
				dkim_error(dkim,
				           "d=/i= mismatch on signature generation");
				return 0;
			}
			else
			{
				nosigner = TRUE;
			}
		}
	}

	/*
	**  We need to generate a DKIM-Signature: header template
	**  and include it in the canonicalization.
	*/

	/* basic required stuff */
	if (sizeof(sig->sig_timestamp) == sizeof(unsigned long long))
		format = "v=%s;%sa=%s;%sc=%s/%s;%sd=%s;%ss=%s;%st=%llu";
	else if (sizeof(sig->sig_timestamp) == sizeof(unsigned long))
		format = "v=%s;%sa=%s;%sc=%s/%s;%sd=%s;%ss=%s;%st=%lu";
	else 
		format = "v=%s;%sa=%s;%sc=%s/%s;%sd=%s;%ss=%s;%st=%u";

	v = DKIM_VERSION_SIG;
#ifdef _FFR_CONDITIONAL
	if (dkim->dkim_conditional != NULL)
		v = DKIM_VERSION_SIG2;
	if (dkim->dkim_xtags != NULL)
	{
		struct dkim_xtag *xt;

		for (xt = dkim->dkim_xtags; xt != NULL; xt = xt->xt_next)
		{
			if (xt->xt_tag[0] == '!')
			{
				v = DKIM_VERSION_SIG2;
				break;
			}
		}
	}
#endif /* _FFR_CONDITIONAL */

	(void) dkim_dstring_printf(dstr, format,
	                           v, delim,
	                           dkim_code_to_name(algorithms,
	                                             sig->sig_signalg),
	                           delim,
	                           dkim_code_to_name(canonicalizations,
	                                             sig->sig_hdrcanonalg),
	                           dkim_code_to_name(canonicalizations,
	                                             sig->sig_bodycanonalg),
	                           delim,
	                           sig->sig_domain, delim,
	                           sig->sig_selector, delim,
	                           sig->sig_timestamp);

	if (dkim->dkim_querymethods != NULL)
	{
		_Bool firstq = TRUE;
		struct dkim_qmethod *q;

		for (q = dkim->dkim_querymethods; q != NULL; q = q->qm_next)
		{
			if (firstq)
			{
				dkim_dstring_printf(dstr, ";%sq=%s", delim,
						    q->qm_type);
			}
			else
			{
				dkim_dstring_printf(dstr, ":%s", q->qm_type);
			}

			if (q->qm_options)
			{
				dkim_dstring_printf(dstr, "/%s",
				                    q->qm_options);
			}

			firstq = FALSE;
		}
	}

	if (dkim->dkim_libhandle->dkiml_sigttl != 0)
	{
		uint64_t expire;

		expire = sig->sig_timestamp + dkim->dkim_libhandle->dkiml_sigttl;
		if (sizeof(expire) == sizeof(unsigned long long))
			dkim_dstring_printf(dstr, ";%sx=%llu", delim, expire);
		else if (sizeof(expire) == sizeof(unsigned long))
			dkim_dstring_printf(dstr, ";%sx=%lu", delim, expire);
		else
			dkim_dstring_printf(dstr, ";%sx=%u", delim, expire);
	}

	if (dkim->dkim_signer != NULL && !nosigner)
	{
		dkim_dstring_printf(dstr, ";%si=%s", delim,
		                    dkim->dkim_signer);
	}

#ifdef _FFR_CONDITIONAL
	if (dkim->dkim_conditional != NULL)
	{
		dkim_dstring_printf(dstr, ";%s!cd=%s", delim,
		                    dkim->dkim_conditional);
	}

#endif /* _FFR_CONDITIONAL */

	if (dkim->dkim_xtags != NULL)
	{
		struct dkim_xtag *x;

		for (x = dkim->dkim_xtags; x != NULL; x = x->xt_next)
		{
			dkim_dstring_printf(dstr, ";%s%s=%s", delim,
			                    x->xt_tag, x->xt_value);
		}
	}

	memset(b64hash, '\0', sizeof b64hash);

	status = dkim_canon_closebody(dkim);
	if (status != DKIM_STAT_OK)
		return 0;

	status = dkim_canon_getfinal(sig->sig_bodycanon, &hash, &hashlen);
	if (status != DKIM_STAT_OK)
	{
		dkim_error(dkim, "dkim_canon_getfinal() failed");
		return (size_t) -1;
	}

	status = dkim_base64_encode(hash, hashlen,
	                            b64hash, sizeof b64hash);

	dkim_dstring_printf(dstr, ";%sbh=%s", delim, b64hash);

	/* l= */
	if (dkim->dkim_partial)
	{
		dkim_dstring_printf(dstr, ";%sl=%lu", delim,
		                    (u_long) sig->sig_bodycanon->canon_wrote);
	}

	/* h= */
	firsthdr = TRUE;
	for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if ((hdr->hdr_flags & DKIM_HDR_SIGNED) == 0)
			continue;

		if (!firsthdr)
		{
			dkim_dstring_cat1(dstr, ':');
		}
		else
		{
			dkim_dstring_cat1(dstr, ';');
			dkim_dstring_catn(dstr, (u_char *) delim, delimlen);
			dkim_dstring_catn(dstr, (u_char *) "h=", 2);
		}

		firsthdr = FALSE;

		dkim_dstring_catn(dstr, hdr->hdr_text, hdr->hdr_namelen);
	}

	if (dkim->dkim_libhandle->dkiml_oversignhdrs != NULL &&
	    dkim->dkim_libhandle->dkiml_oversignhdrs[0] != NULL)
	{
		_Bool wrote = FALSE;

		if (firsthdr)
		{
			dkim_dstring_cat1(dstr, ';');
			dkim_dstring_catn(dstr, delim, delimlen);
			dkim_dstring_catn(dstr, "h=", 2);
		}
		else
		{
			dkim_dstring_cat1(dstr, ':');
		}

		for (n = 0;
		     dkim->dkim_libhandle->dkiml_oversignhdrs[n] != NULL;
		     n++)
		{
			if (dkim->dkim_libhandle->dkiml_oversignhdrs[n][0] == '\0')
				continue;

			if (wrote)
				dkim_dstring_cat1(dstr, ':');

			dkim_dstring_cat(dstr,
			                 dkim->dkim_libhandle->dkiml_oversignhdrs[n]);

			wrote = TRUE;
		}
	}

	/* if reports were requested, stick that in too */
	if (dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_REQUESTREPORTS)
		dkim_dstring_printf(dstr, ";%sr=y", delim);

	/* if diagnostic headers were requested, include 'em */
	if (dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_ZTAGS)
	{
		_Bool first;
		int status;
		int len;
		u_char *hend;
		u_char *colon;
		unsigned char name[DKIM_MAXHEADER + 1];

		dkim_dstring_cat1(dstr, ';');
		dkim_dstring_catn(dstr, (u_char *) delim, delimlen);
		dkim_dstring_catn(dstr, (u_char *) "z=", 2);

		first = TRUE;

		for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			/* apply "skip" header and "sign" header lists */
			hend = hdr->hdr_text + hdr->hdr_textlen;
			colon = memchr(hdr->hdr_text, ':', hdr->hdr_textlen);
			if (colon != NULL)
			{
				hend = colon;

				while (hend > hdr->hdr_text &&
				       isascii(*(hend - 1)) &&
				       isspace(*(hend - 1)))
					hend--;
			}

			strlcpy((char *) name, (char *) hdr->hdr_text,
			        sizeof name);
			if (hend != NULL)
				name[hend - hdr->hdr_text] = '\0';

			if (dkim->dkim_libhandle->dkiml_skipre)
			{
				status = regexec(&dkim->dkim_libhandle->dkiml_skiphdrre,
				                 (char *) name, 0, NULL, 0);

				if (status == 0)
					continue;
				else
					assert(status == REG_NOMATCH);
			}

			if (dkim->dkim_libhandle->dkiml_signre)
			{
				status = regexec(&dkim->dkim_libhandle->dkiml_hdrre,
				                 (char *) name, 0, NULL, 0);

				if (status == REG_NOMATCH)
					continue;
				else
					assert(status == 0);
			}

			if (!first)
			{
				dkim_dstring_cat1(dstr, '|');
			}

			first = FALSE;

			len = dkim_qp_encode(hdr->hdr_text, tmp, sizeof tmp);

			if (len > 0)
				dkim_dstring_catn(dstr, tmp, (size_t) len);
		}
	}

	/* and finally, an empty b= */
	dkim_dstring_cat1(dstr, ';');
	dkim_dstring_catn(dstr, (u_char *) delim, delimlen);
	dkim_dstring_catn(dstr, (u_char *) "b=", 2);

	return dkim_dstring_len(dstr);
}

/*
**  DKIM_GETSENDER -- determine sender and store it in the handle
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

static DKIM_STAT
dkim_getsender(DKIM *dkim)
{
	int c;
	size_t hlen;
	DKIM_STAT status;
	unsigned char *domain;
	unsigned char *user;
	struct dkim_header *sender = NULL;
	struct dkim_header *cur;

	assert(dkim != NULL);

	if (dkim->dkim_sender != NULL)
		return DKIM_STAT_OK;

	for (cur = dkim->dkim_hhead; cur != NULL; cur = cur->hdr_next)
	{
		if (cur->hdr_namelen == 4 &&
		    strncasecmp("from", (char *) cur->hdr_text, 4) == 0)
		{
			sender = cur;
			break;
		}
	}

	if (sender == NULL)
	{
		dkim_error(dkim, "no from header field detected");
		return DKIM_STAT_SYNTAX;
	}
	dkim->dkim_senderhdr = sender;

	if (sender->hdr_colon == NULL)
	{
		dkim_error(dkim, "syntax error in headers");
		return DKIM_STAT_SYNTAX;
	}

	dkim->dkim_sender = dkim_strdup(dkim, sender->hdr_colon + 1, 0);
	if (dkim->dkim_sender == NULL)
		return DKIM_STAT_NORESOURCE;

	status = dkim_mail_parse(dkim->dkim_sender, &user, &domain);
	if (status != 0 || domain == NULL || user == NULL ||
	    domain[0] == '\0' || user[0] == '\0')
	{
		dkim_error(dkim, "can't determine sender address");
		return DKIM_STAT_SYNTAX;
	}

	if (dkim->dkim_domain == NULL)
	{
		dkim->dkim_domain = dkim_strdup(dkim, domain, 0);
		if (dkim->dkim_domain == NULL)
			return DKIM_STAT_NORESOURCE;
	}

	dkim->dkim_user = dkim_strdup(dkim, user, 0);
	if (dkim->dkim_user == NULL)
		return DKIM_STAT_NORESOURCE;

	return DKIM_STAT_OK;
}

/*
**  DKIM_GET_KEY -- acquire a public key used for verification
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	test -- skip signature-specific validity checks
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_get_key(DKIM *dkim, DKIM_SIGINFO *sig, _Bool test)
{
	_Bool gotkey = FALSE;			/* key stored */
	_Bool gotset = FALSE;			/* set parsed */
	_Bool gotreply = FALSE;			/* reply received */
	int status;
	int c;
	DKIM_SIGINFO *osig;
	struct dkim_set *set = NULL;
	struct dkim_set *nextset;
	unsigned char *p;
	unsigned char buf[BUFRSZ + 1];

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(sig->sig_selector != NULL);
	assert(sig->sig_domain != NULL);

	memset(buf, '\0', sizeof buf);

	/* see if one of the other signatures already has the key we need */
	for (c = 0; c < dkim->dkim_sigcount; c++)
	{
		osig = dkim->dkim_siglist[c];

		/* don't self-search */
		if (sig == osig)
			continue;

		/* skip unprocessed signatures */
		if ((osig->sig_flags & DKIM_SIGFLAG_PROCESSED) == 0)
			continue;

		/* skip unless selector and domain match */
		if (strcmp((char *) osig->sig_domain,
		           (char *) sig->sig_domain) != 0 ||
		    strcmp((char *) osig->sig_selector,
		           (char *) sig->sig_selector) != 0)
			continue;

		/* we got a match!  copy the key data (if any)... */
		if (osig->sig_key != NULL)
		{
			sig->sig_key = DKIM_MALLOC(dkim, osig->sig_b64keylen);
			if (sig->sig_key == NULL)
			{
				dkim_error(dkim,
				           "unable to allocate %d byte(s)",
				           osig->sig_b64keylen);
				return DKIM_STAT_NORESOURCE;
			}

			memcpy(sig->sig_key, osig->sig_key,
			       osig->sig_b64keylen);

			sig->sig_keylen = osig->sig_keylen;

			gotkey = TRUE;
		}

		/* ...and the key tag list (if any) */
		if (osig->sig_keytaglist != NULL)
		{
			sig->sig_keytaglist = osig->sig_keytaglist;
			set = sig->sig_keytaglist;

			gotset = TRUE;
			gotreply = TRUE;
		}

		break;
	}

	/* try a local function if there was one defined */
	if (!gotkey && dkim->dkim_libhandle->dkiml_key_lookup != NULL)
	{
		DKIM_CBSTAT cbstatus;

		cbstatus = dkim->dkim_libhandle->dkiml_key_lookup(dkim,
		                                                  sig,
		                                                  buf,
		                                                  sizeof buf);
		switch (cbstatus)
		{
		  case DKIM_CBSTAT_CONTINUE:
			gotreply = TRUE;
			break;

		  case DKIM_CBSTAT_REJECT:
			return DKIM_STAT_CBREJECT;

		  case DKIM_CBSTAT_TRYAGAIN:
			return DKIM_STAT_CBTRYAGAIN;

		  case DKIM_CBSTAT_NOTFOUND:
			return DKIM_STAT_NOKEY;

		  case DKIM_CBSTAT_ERROR:
			return DKIM_STAT_CBERROR;

		  case DKIM_CBSTAT_DEFAULT:
			break;

		  default:
			return DKIM_STAT_CBINVALID;
		}
	}

	/* if no local function or it returned no result, make the query */
	if (!gotreply)
	{
		/* use appropriate get method */
		switch (sig->sig_query)
		{
		  case DKIM_QUERY_DNS:
			status = (int) dkim_get_key_dns(dkim, sig, buf,
			                                sizeof buf);
			if (status != (int) DKIM_STAT_OK)
				return (DKIM_STAT) status;
			break;

		  case DKIM_QUERY_FILE:
			status = (int) dkim_get_key_file(dkim, sig, buf,
			                                 sizeof buf);
			if (status != (int) DKIM_STAT_OK)
				return (DKIM_STAT) status;
			break;

		  default:
			assert(0);
		}
	}

	/* decode the payload */
	if (!gotset)
	{
		if (buf[0] == '\0')
		{
			dkim_error(dkim, "empty key record");
			return DKIM_STAT_SYNTAX;
		}

		status = dkim_process_set(dkim, DKIM_SETTYPE_KEY, buf,
		                          strlen((char *) buf), NULL, FALSE,
		                          NULL);
		if (status != DKIM_STAT_OK)
			return status;

		/* get the last key */
		set = dkim_set_first(dkim, DKIM_SETTYPE_KEY);
		assert(set != NULL);
		for (;;)
		{
			nextset = dkim_set_next(set, DKIM_SETTYPE_KEY);
			if (nextset == NULL)
				break;
			set = nextset;
		}
		assert(set != NULL);

		sig->sig_keytaglist = set;
	}

	/* verify key version first */
	p = dkim_param_get(set, (u_char *) "v");
	if (p != NULL && strcmp((char *) p, DKIM_VERSION_KEY) != 0)
	{
		dkim_error(dkim, "invalid key version '%s'", p);
		sig->sig_error = DKIM_SIGERROR_KEYVERSION;
		return DKIM_STAT_SYNTAX;
	}

	/* then make sure the hash type is something we can handle */
	p = dkim_param_get(set, (u_char *) "h");
	if (!dkim_key_hashesok(dkim->dkim_libhandle, p))
	{
		dkim_error(dkim, "unknown hash '%s'", p);
		sig->sig_error = DKIM_SIGERROR_KEYUNKNOWNHASH;
		return DKIM_STAT_SYNTAX;
	}
	/* ...and that this key is approved for this signature's hash */
	else if (!test && !dkim_key_hashok(sig, p))
	{
		dkim_error(dkim, "signature-key hash mismatch");
		sig->sig_error = DKIM_SIGERROR_KEYHASHMISMATCH;
		return DKIM_STAT_CANTVRFY;
	}

	/* make sure it's a key designated for e-mail */
	if (!dkim_key_smtp(set))
	{
		dkim_error(dkim, "key type mismatch");
		sig->sig_error = DKIM_SIGERROR_NOTEMAILKEY;
		return DKIM_STAT_CANTVRFY;
	}

	/* then key type */
	p = dkim_param_get(set, (u_char *) "k");
	if (p == NULL)
	{
		dkim_error(dkim, "key type missing");
		sig->sig_error = DKIM_SIGERROR_KEYTYPEMISSING;
		return DKIM_STAT_SYNTAX;
	}
	else if (dkim_name_to_code(keytypes, (char *) p) == -1)
	{
		dkim_error(dkim, "unknown key type '%s'", p);
		sig->sig_error = DKIM_SIGERROR_KEYTYPEUNKNOWN;
		return DKIM_STAT_SYNTAX;
	}

	if (!gotkey)
	{
		/* decode the key */
		sig->sig_b64key = dkim_param_get(set, (u_char *) "p");
		if (sig->sig_b64key == NULL)
		{
			dkim_error(dkim, "key missing");
			return DKIM_STAT_SYNTAX;
		}
		else if (sig->sig_b64key[0] == '\0')
		{
			return DKIM_STAT_REVOKED;
		}
		sig->sig_b64keylen = strlen((char *) sig->sig_b64key);

		sig->sig_key = DKIM_MALLOC(dkim, sig->sig_b64keylen);
		if (sig->sig_key == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           sig->sig_b64keylen);
			return DKIM_STAT_NORESOURCE;
		}

		status = dkim_base64_decode(sig->sig_b64key, sig->sig_key,
		                            sig->sig_b64keylen);
		if (status < 0)
		{
			dkim_error(dkim, "key missing");
			return DKIM_STAT_SYNTAX;
		}

		sig->sig_keylen = status;
	}

	/* store key flags */
	p = dkim_param_get(set, (u_char *) "t");
	if (p != NULL)
	{
		u_int flag;
		char *t;
		char *last;
		char tmp[BUFRSZ + 1];

		strlcpy(tmp, (char *) p, sizeof tmp);

		for (t = strtok_r(tmp, ":", &last);
		     t != NULL;
		     t = strtok_r(NULL, ":", &last))
		{
			flag = (u_int) dkim_name_to_code(keyflags, t);
			if (flag != (u_int) -1)
				sig->sig_flags |= flag;
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_HEADERCHECK -- check header validity
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	TRUE iff the header meets sanity checks.
*/

static _Bool
dkim_headercheck(DKIM *dkim)
{
	struct dkim_header *hdr;

	assert(dkim != NULL);

	if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_STRICTHDRS) != 0)
	{
		int status;
		unsigned char *user;
		unsigned char *domain;
		unsigned char *tmp;

		/* Date (must be exactly one) */
		hdr = dkim_get_header(dkim, "Date", 4, 0);
		if (hdr == NULL)
		{
			dkim_error(dkim, "Date: header field absent");
			return FALSE;
		}

		hdr = dkim_get_header(dkim, "Date", 4, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple Date: header fields present");
			return FALSE;
		}

		/* From (must be exactly one) */
		hdr = dkim_get_header(dkim, "From", 4, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple From: header fields present");
			return FALSE;
		}

		hdr = dkim_get_header(dkim, "From", 4, 0);
		if (hdr == NULL)
		{
			dkim_error(dkim, "From: header field absent");
			return FALSE;
		}

		/* confirm it's parsable */
		tmp = strdup(hdr->hdr_colon + 1);
		if (tmp != NULL)
		{
			status = dkim_mail_parse(tmp, &user, &domain);
			if (status != 0 ||
			    user == NULL || user[0] == '\0' ||
			    domain == NULL || domain[0] == '\0')
			{
				dkim_error(dkim, "From: header field cannot be parsed");
				return FALSE;
			}

			free(tmp);
		}

		/* Sender (no more than one) */
		hdr = dkim_get_header(dkim, "Sender", 6, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple Sender: header fields present");
			return FALSE;
		}

		/* Reply-To (no more than one) */
		hdr = dkim_get_header(dkim, "Reply-To", 8, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple Reply-To: header fields present");
			return FALSE;
		}

		/* To (no more than one) */
		hdr = dkim_get_header(dkim, "To", 2, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple To: header fields present");
			return FALSE;
		}

		/* Cc (no more than one) */
		hdr = dkim_get_header(dkim, "Cc", 2, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple Cc: header fields present");
			return FALSE;
		}

		/* Bcc (should we even bother?) */
		hdr = dkim_get_header(dkim, "Bcc", 3, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple Bcc: header fields present");
			return FALSE;
		}

		/* Message-ID (no more than one) */
		hdr = dkim_get_header(dkim, "Message-ID", 10, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple Message-ID: header fields present");
			return FALSE;
		}

		/* In-Reply-To (no more than one) */
		hdr = dkim_get_header(dkim, "In-Reply-To", 11, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple In-Reply-To: header fields present");
			return FALSE;
		}

		/* References (no more than one) */
		hdr = dkim_get_header(dkim, "References", 10, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple References: header fields present");
			return FALSE;
		}

		/* Subject (no more than one) */
		hdr = dkim_get_header(dkim, "Subject", 7, 1);
		if (hdr != NULL)
		{
			dkim_error(dkim,
			           "multiple Subject: header fields present");
			return FALSE;
		}
	}

	return TRUE;
}

/*
**  DKIM_EOH_SIGN -- declare end-of-headers; prepare for signing
** 
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

static DKIM_STAT
dkim_eoh_sign(DKIM *dkim)
{
	_Bool keep;
	_Bool tmp;
	u_char *hn = NULL;
	DKIM_STAT status;
	int hashtype = DKIM_HASHTYPE_UNKNOWN;
	DKIM_CANON *bc;
	DKIM_CANON *hc;
	DKIM_LIB *lib;

	assert(dkim != NULL);

#ifdef _FFR_RESIGN
	if (dkim->dkim_resign != NULL && dkim->dkim_hdrbind)
		return DKIM_STAT_INVALID;
#endif /* _FFR_RESIGN */

	if (dkim->dkim_state >= DKIM_STATE_EOH2)
		return DKIM_STAT_INVALID;
	if (dkim->dkim_state < DKIM_STATE_EOH2)
		dkim->dkim_state = DKIM_STATE_EOH2;

	lib = dkim->dkim_libhandle;
	assert(lib != NULL);

	tmp = ((lib->dkiml_flags & DKIM_LIBFLAGS_TMPFILES) != 0);
	keep = ((lib->dkiml_flags & DKIM_LIBFLAGS_KEEPFILES) != 0);

	dkim->dkim_version = lib->dkiml_version;

	/* check for header validity */
	if (!dkim_headercheck(dkim))
	{
		dkim->dkim_state = DKIM_STATE_UNUSABLE;
		return DKIM_STAT_SYNTAX;
	}

	/*
	**  Verify that all the required headers are present and
	**  marked for signing.
	*/

	hn = (u_char *) dkim_check_requiredhdrs(dkim);
	if (hn != NULL)
	{
		dkim_error(dkim, "required header \"%s\" not found", hn);
		dkim->dkim_state = DKIM_STATE_UNUSABLE;
		return DKIM_STAT_SYNTAX;
	}

	/* determine hash type */
	switch (dkim->dkim_signalg)
	{
	  case DKIM_SIGN_RSASHA1:
		hashtype = DKIM_HASHTYPE_SHA1;
		break;

	  case DKIM_SIGN_RSASHA256:
	  case DKIM_SIGN_ED25519SHA256:
		hashtype = DKIM_HASHTYPE_SHA256;
		break;

	  default:
		assert(0);
		/* NOTREACHED */
	}

	if (dkim->dkim_siglist == NULL)
	{
		/* initialize signature and canonicalization for signing */
		dkim->dkim_siglist = DKIM_MALLOC(dkim, sizeof(DKIM_SIGINFO **));
		if (dkim->dkim_siglist == NULL)
		{
			dkim_error(dkim, "failed to allocate %d byte(s)",
			           sizeof(DKIM_SIGINFO *));
			return DKIM_STAT_NORESOURCE;
		}

		dkim->dkim_siglist[0] = DKIM_MALLOC(dkim,
		                                    sizeof(struct dkim_siginfo));
		if (dkim->dkim_siglist[0] == NULL)
		{
			dkim_error(dkim, "failed to allocate %d byte(s)",
			           sizeof(struct dkim_siginfo));
			return DKIM_STAT_NORESOURCE;
		}
		dkim->dkim_sigcount = 1;
		memset(dkim->dkim_siglist[0], '\0',
		       sizeof(struct dkim_siginfo));
		dkim->dkim_siglist[0]->sig_domain = dkim->dkim_domain;
		dkim->dkim_siglist[0]->sig_selector = dkim->dkim_selector;
		dkim->dkim_siglist[0]->sig_hashtype = hashtype;
		dkim->dkim_siglist[0]->sig_signalg = dkim->dkim_signalg;

		status = dkim_add_canon(dkim, TRUE, dkim->dkim_hdrcanonalg,
		                        hashtype, NULL, NULL, 0, &hc);
		if (status != DKIM_STAT_OK)
			return status;

		status = dkim_add_canon(dkim, FALSE, dkim->dkim_bodycanonalg,
		                        hashtype, NULL, NULL,
		                        dkim->dkim_signlen, &bc);
		if (status != DKIM_STAT_OK)
			return status;

		dkim->dkim_siglist[0]->sig_hdrcanon = hc;
		dkim->dkim_siglist[0]->sig_hdrcanonalg = dkim->dkim_hdrcanonalg;
		dkim->dkim_siglist[0]->sig_bodycanon = bc;
		dkim->dkim_siglist[0]->sig_bodycanonalg = dkim->dkim_bodycanonalg;

		if (dkim->dkim_libhandle->dkiml_fixedtime != 0)
		{
			dkim->dkim_siglist[0]->sig_timestamp = dkim->dkim_libhandle->dkiml_fixedtime;
		}
		else
		{
			time_t now;

			(void) time(&now);

			dkim->dkim_siglist[0]->sig_timestamp = (uint64_t) now;
		}
	}

	/* initialize all canonicalizations */
	status = dkim_canon_init(dkim, tmp, keep);
	if (status != DKIM_STAT_OK)
		return status;

	/* run the headers */
	status = dkim_canon_runheaders(dkim);
	if (status != DKIM_STAT_OK)
		return status;

	return DKIM_STAT_OK;
}

/*
**  DKIM_EOH_VERIFY -- declare end-of-headers; set up verification
** 
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

static DKIM_STAT
dkim_eoh_verify(DKIM *dkim)
{
	_Bool keep;
	_Bool tmp;
	_Bool bsh;
	DKIM_STAT status;
	int c;
	DKIM_LIB *lib;
	DKIM_SET *set;

	assert(dkim != NULL);

	if (dkim->dkim_state >= DKIM_STATE_EOH2)
		return DKIM_STAT_INVALID;
	if (dkim->dkim_state < DKIM_STATE_EOH1)
		dkim->dkim_state = DKIM_STATE_EOH1;

	lib = dkim->dkim_libhandle;
	assert(lib != NULL);

	bsh = ((lib->dkiml_flags & DKIM_LIBFLAGS_BADSIGHANDLES) != 0);
	tmp = ((lib->dkiml_flags & DKIM_LIBFLAGS_TMPFILES) != 0);
	keep = ((lib->dkiml_flags & DKIM_LIBFLAGS_KEEPFILES) != 0);

	/* populate some stuff like dkim_sender, dkim_domain, dkim_user */
	status = dkim_getsender(dkim);
	if (status != DKIM_STAT_OK && !bsh)
	{
		dkim->dkim_state = DKIM_STATE_UNUSABLE;
		return status;
	}

	/* check for header validity */
	if (!dkim_headercheck(dkim))
	{
		dkim->dkim_state = DKIM_STATE_UNUSABLE;
		return DKIM_STAT_SYNTAX;
	}

	/* allocate the siginfo array if not already done */
	if (dkim->dkim_siglist == NULL)
	{
		/* count the signatures */
		for (set = dkim_set_first(dkim, DKIM_SETTYPE_SIGNATURE);
		     set != NULL;
		     set = dkim_set_next(set, DKIM_SETTYPE_SIGNATURE))
		{
			if (!set->set_bad || bsh)
				dkim->dkim_sigcount++;
		}

		/* if no signatures, return such */
		if (dkim->dkim_sigcount == 0)
		{
			dkim->dkim_skipbody = TRUE;
			return DKIM_STAT_NOSIG;
		}

		status = dkim_siglist_setup(dkim);
		if (status != DKIM_STAT_OK)
			return status;

		/* initialize all discovered canonicalizations */
		status = dkim_canon_init(dkim, tmp, keep);
		if (status != DKIM_STAT_OK)
			return status;
	}

	/* call the prescreen callback, if defined */
	if (lib->dkiml_prescreen != NULL && !dkim->dkim_eoh_reentry)
	{
		status = lib->dkiml_prescreen(dkim,
		                              dkim->dkim_siglist,
		                              dkim->dkim_sigcount);
		switch (status)
		{
		  case DKIM_CBSTAT_CONTINUE:
		  case DKIM_CBSTAT_DEFAULT:
			break;

		  case DKIM_CBSTAT_REJECT:
			return DKIM_STAT_CBREJECT;

		  case DKIM_CBSTAT_TRYAGAIN:
			return DKIM_STAT_CBTRYAGAIN;

		  case DKIM_CBSTAT_ERROR:
			return DKIM_STAT_CBERROR;

		  default:
			return DKIM_STAT_CBINVALID;
		}
	}

	/* if set to ignore everything, treat message as unsigned */
	set = NULL;
	for (c = 0; c < dkim->dkim_sigcount; c++)
	{
		if (!(dkim->dkim_siglist[c]->sig_flags & DKIM_SIGFLAG_IGNORE))
		{
			set = dkim->dkim_siglist[c]->sig_taglist;
			break;
		}
	}

	if (set == NULL)
	{
		dkim->dkim_skipbody = TRUE;
		dkim->dkim_state = DKIM_STATE_EOH2;
		return DKIM_STAT_NOSIG;
	}

	/* run the headers */
	if (!dkim->dkim_eoh_reentry)
	{
		status = dkim_canon_runheaders(dkim);
		if (status != DKIM_STAT_OK)
			return status;
	}

	/* do public key verification of all still-enabled signatures here */
	if ((lib->dkiml_flags & DKIM_LIBFLAGS_DELAYSIGPROC) == 0)
	{
		for (c = 0; c < dkim->dkim_sigcount; c++)
		{
			if (!(dkim->dkim_siglist[c]->sig_flags & DKIM_SIGFLAG_PROCESSED) &&
			    !(dkim->dkim_siglist[c]->sig_flags & DKIM_SIGFLAG_IGNORE) &&
			    dkim->dkim_siglist[c]->sig_error == DKIM_SIGERROR_UNKNOWN)
			{
				status = dkim_sig_process(dkim,
				                          dkim->dkim_siglist[c]);
				if (status != DKIM_STAT_OK)
				{
					if (status == DKIM_STAT_CBTRYAGAIN)
						dkim->dkim_eoh_reentry = TRUE;

					return status;
				}
			}
		}
	}

	/* no re-entries beyond this point */
	dkim->dkim_state = DKIM_STATE_EOH2;

	/*
	**  Possible short-circuit here if all signatures are:
	**  - marked to be ignored
	**  - definitely invalid
	**  - verification attempted but failed
	*/

	if ((lib->dkiml_flags & DKIM_LIBFLAGS_EOHCHECK) != 0)
	{
		_Bool good = FALSE;
		DKIM_SIGINFO *sig;

		for (c = 0; c < dkim->dkim_sigcount; c++)
		{
			sig = dkim->dkim_siglist[c];

			/* ignored? */
			if ((sig->sig_flags & DKIM_SIGFLAG_IGNORE) != 0)
				continue;

			/* had a processing error? */
			if (sig->sig_error != DKIM_SIGERROR_UNKNOWN &&
			    sig->sig_error != DKIM_SIGERROR_OK)
				continue;

			/* processed but didn't pass? */
			if ((sig->sig_flags & DKIM_SIGFLAG_PROCESSED) != 0 &&
			    (sig->sig_flags & DKIM_SIGFLAG_PASSED) == 0)
				continue;

			/* OK we had a good one */
			good = TRUE;
			break;
		}

		/* no good ones */
		if (!good)
		{
			/* report error on the last one */
			if (sig->sig_error != DKIM_SIGERROR_UNKNOWN &&
			    sig->sig_error != DKIM_SIGERROR_OK)
			{
				dkim_error(dkim,
				           dkim_code_to_name(sigerrors,
				                             sig->sig_error));
			}

			return DKIM_STAT_CANTVRFY;
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_EOM_SIGN -- declare end-of-body; complete signing
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

static DKIM_STAT
dkim_eom_sign(DKIM *dkim)
{
	int status;
	size_t l = 0;
	size_t diglen;
	size_t siglen = 0;
	size_t len;
	DKIM_STAT ret;
	u_char *digest;
	u_char *sighdr;
	u_char *signature = NULL;
	DKIM_SIGINFO *sig;
	DKIM_CANON *hc;
	struct dkim_dstring *tmphdr;
	struct dkim_crypto *crypto = NULL;
	struct dkim_header hdr;

	assert(dkim != NULL);

#ifdef _FFR_RESIGN
	if (dkim->dkim_resign != NULL)
	{
		if (dkim->dkim_hdrbind)
		{
			if (dkim->dkim_state != DKIM_STATE_INIT ||
			    dkim->dkim_resign->dkim_state != DKIM_STATE_EOM2)
				return DKIM_STAT_INVALID;
		}
		else
		{
			if (dkim->dkim_state < DKIM_STATE_EOH1 ||
			    dkim->dkim_resign->dkim_state != DKIM_STATE_EOM2)
				return DKIM_STAT_INVALID;
		}
	}
	else if (dkim->dkim_state >= DKIM_STATE_EOM2 ||
	         dkim->dkim_state < DKIM_STATE_EOH1)
	{
  		return DKIM_STAT_INVALID;
	}
#else /* _FFR_RESIGN */
	if (dkim->dkim_state >= DKIM_STATE_EOM2 ||
	    dkim->dkim_state < DKIM_STATE_EOH1)
		return DKIM_STAT_INVALID;
#endif /* _FFR_RESIGN */

	if (dkim->dkim_chunkstate != DKIM_CHUNKSTATE_INIT &&
	    dkim->dkim_chunkstate != DKIM_CHUNKSTATE_DONE)
		return DKIM_STAT_INVALID;

  	if (dkim->dkim_state < DKIM_STATE_EOM2)
  		dkim->dkim_state = DKIM_STATE_EOM2;

#ifdef _FFR_RESIGN
	if (dkim->dkim_resign != NULL)
	{
		_Bool found = FALSE;
		int c;
		char *hn;

		/*
		**  Verify that all the required headers are present and
		**  marked for signing.
		*/

		hn = (u_char *) dkim_check_requiredhdrs(dkim);
		if (hn != NULL)
		{
			dkim_error(dkim, "required header \"%s\" not found",
			           hn);
			dkim->dkim_state = DKIM_STATE_UNUSABLE;
			return DKIM_STAT_SYNTAX;
		}

		/*
		**  Fail if the verification handle didn't work.  For a
		**  multiply-signed message, we only require one passing
		**  signature (for now).
		*/

		if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_STRICTRESIGN) != 0)
		{
			for (c = 0; c < dkim->dkim_resign->dkim_sigcount; c++)
			{
				sig = dkim->dkim_resign->dkim_siglist[c];
				if ((sig->sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
				    sig->sig_bh == DKIM_SIGBH_MATCH)
				{
					found = TRUE;
					break;
				}
			}

			if (!found)
				return DKIM_STAT_CANTVRFY;
		}
	}
#endif /* _FFR_RESIGN */

	/* finalize body canonicalizations */
	status = dkim_canon_closebody(dkim);
	if (status != DKIM_STAT_OK)
		return status;

	dkim->dkim_bodydone = TRUE;

	/* set signature timestamp */
	if (dkim->dkim_libhandle->dkiml_fixedtime != 0)
	{
		dkim->dkim_timestamp = dkim->dkim_libhandle->dkiml_fixedtime;
	}
	else
	{
		time_t now;

		(void) time(&now);
		dkim->dkim_timestamp = (uint64_t) now;
	}

	/* sign with l= if requested */
	if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_SIGNLEN) != 0)
		dkim->dkim_partial = TRUE;

	/* get signature and canonicalization handles */
	assert(dkim->dkim_siglist != NULL);
	assert(dkim->dkim_siglist[0] != NULL);
	sig = dkim->dkim_siglist[0];
	hc = sig->sig_hdrcanon;

	if (dkim->dkim_keydata == NULL)
	{
		if (dkim_privkey_load(dkim) != DKIM_STAT_OK)
			return DKIM_STAT_NORESOURCE;
	}

	crypto = dkim->dkim_keydata;
#ifdef USE_GNUTLS
	if (crypto->crypto_privkey == NULL)
#else /* USE_GNUTLS */
	if (!(crypto->crypto_key != NULL ||
	      (sig->sig_signalg == DKIM_SIGN_ED25519SHA256 &&
	       crypto->crypto_pkey != NULL)))
#endif /* USE_GNUTLS */
	{
		dkim_error(dkim, "private key load failed");
		return DKIM_STAT_NORESOURCE;
	}

	sig->sig_keybits = crypto->crypto_keysize;
	sig->sig_signature = dkim->dkim_keydata;
	sig->sig_flags |= DKIM_SIGFLAG_KEYLOADED;

	if (sig->sig_signalg != DKIM_SIGN_ED25519SHA256 &&
	    sig->sig_keybits < dkim->dkim_libhandle->dkiml_minkeybits)
	{
		sig->sig_error = DKIM_SIGERROR_KEYTOOSMALL;
		dkim_error(dkim,
		           "private key too small (%d bits, need at least %d)",
		           sig->sig_keybits,
		           dkim->dkim_libhandle->dkiml_minkeybits);
		return DKIM_STAT_SIGGEN;
	}

	switch (sig->sig_signalg)
	{
	  case DKIM_SIGN_RSASHA1:
	  case DKIM_SIGN_RSASHA256:
	  {
		assert(sig->sig_hashtype == DKIM_HASHTYPE_SHA1 ||
		       sig->sig_hashtype == DKIM_HASHTYPE_SHA256);

		if (sig->sig_hashtype == DKIM_HASHTYPE_SHA256)
		{
			assert(dkim_libfeature(dkim->dkim_libhandle,
		                               DKIM_FEATURE_SHA256));
		}

		sig->sig_signature = (void *) dkim->dkim_keydata;
		sig->sig_keytype = DKIM_KEYTYPE_RSA;

		break;
	  }

	  case DKIM_SIGN_ED25519SHA256:
	  {
		assert(sig->sig_hashtype == DKIM_HASHTYPE_SHA256);

		sig->sig_signature = (void *) dkim->dkim_keydata;
		sig->sig_keytype = DKIM_KEYTYPE_ED25519;

		break;
	  }

	  default:
		assert(0);
	}

	/* construct the DKIM signature header to be canonicalized */
	tmphdr = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
	if (tmphdr == NULL)
		return DKIM_STAT_NORESOURCE;

	dkim_dstring_catn(tmphdr, (u_char *) DKIM_SIGNHEADER ": ",
	                  sizeof DKIM_SIGNHEADER + 1);

	ret = dkim_getsighdr_d(dkim, dkim_dstring_len(tmphdr), &sighdr, &len);
	if (ret != DKIM_STAT_OK)
	{
		dkim_dstring_free(tmphdr);
		return ret;
	}

	dkim_dstring_catn(tmphdr, sighdr, len);
	len = dkim_dstring_len(tmphdr);

	hdr.hdr_text = dkim_dstring_get(tmphdr);
	hdr.hdr_colon = hdr.hdr_text + DKIM_SIGNHEADER_LEN;
	hdr.hdr_namelen = DKIM_SIGNHEADER_LEN;
	hdr.hdr_textlen = len;
	hdr.hdr_flags = 0;
	hdr.hdr_next = NULL;

	/* canonicalize */
	dkim_canon_signature(dkim, &hdr);

	dkim_dstring_free(tmphdr);

	/* finalize */
	ret = dkim_canon_getfinal(hc, &digest, &diglen);
	if (ret != DKIM_STAT_OK)
	{
		dkim_error(dkim, "dkim_canon_getfinal() failed");
		return DKIM_STAT_INTERNAL;
	}

	/* compute and store the signature */
	switch (sig->sig_signalg)
	{
#ifdef USE_GNUTLS
	  case DKIM_SIGN_RSASHA1:
	  case DKIM_SIGN_RSASHA256:
	  {
		int alg;
		gnutls_datum_t dd;
		struct dkim_crypto *crypto;

		crypto = (struct dkim_crypto *) sig->sig_signature;

		dd.data = digest;
		dd.size = diglen;

		if (sig->sig_signalg == DKIM_SIGN_RSASHA1)
			alg = GNUTLS_DIG_SHA1;
		else
			alg = GNUTLS_DIG_SHA256;

		status = gnutls_privkey_sign_hash(crypto->crypto_privkey, alg,
		                                  0, &dd,
		                                  &crypto->crypto_rsaout);
		if (status != GNUTLS_E_SUCCESS)
		{
			dkim_sig_load_ssl_errors(dkim, sig, status);
			dkim_error(dkim,
			           "signature generation failed (status %d)",
			           status);
			return DKIM_STAT_INTERNAL;
		}

		signature = crypto->crypto_rsaout.data;
		siglen = crypto->crypto_rsaout.size;

		break;
	  }
#else /* USE_GNUTLS */
	  case DKIM_SIGN_RSASHA1:
	  case DKIM_SIGN_RSASHA256:
	  {
		int nid;
		struct dkim_crypto *crypto;

		crypto = (struct dkim_crypto *) sig->sig_signature;

		nid = NID_sha1;

		if (dkim_libfeature(dkim->dkim_libhandle,
		                    DKIM_FEATURE_SHA256) &&
		    sig->sig_hashtype == DKIM_HASHTYPE_SHA256)
			nid = NID_sha256;

		status = RSA_sign(nid, digest, diglen,
	                          crypto->crypto_out, (int *) &l,
		                  crypto->crypto_key);
		if (status != 1 || l == 0)
		{
			dkim_load_ssl_errors(dkim, 0);
			dkim_error(dkim,
			           "signature generation failed (status %d, length %d)",
			           status, l);

			RSA_free(crypto->crypto_key);
			BIO_free(crypto->crypto_keydata);

			return DKIM_STAT_INTERNAL;
		}

		crypto->crypto_outlen = l;

		signature = crypto->crypto_out;
		siglen = crypto->crypto_outlen;

		break;
	  }

	  case DKIM_SIGN_ED25519SHA256:
	  {
		EVP_MD_CTX *md_ctx = NULL;
		struct dkim_crypto *crypto;

		crypto = (struct dkim_crypto *) sig->sig_signature;

		md_ctx = EVP_MD_CTX_new();
		if (md_ctx == NULL)
		{
			dkim_load_ssl_errors(dkim, 0);
			dkim_error(dkim,
			           "failed to initialize digest context");

			RSA_free(crypto->crypto_key);
			BIO_free(crypto->crypto_keydata);

			return DKIM_STAT_INTERNAL;
		}

		status = EVP_DigestSignInit(md_ctx, NULL,
		                            NULL, NULL, crypto->crypto_pkey);
		if (status == 1)
		{
			l = crypto->crypto_outlen;
			status = EVP_DigestSign(md_ctx, crypto->crypto_out, &l,
		                                digest, diglen);
		}

		if (status != 1)
		{
			/* dkim_load_ssl_errors(dkim, 0); */
			dkim_error(dkim,
			           "signature generation failed (status %d, length %d, %s)",
			           status, l, ERR_error_string(ERR_get_error(), NULL));

			RSA_free(crypto->crypto_key);
			BIO_free(crypto->crypto_keydata);

			return DKIM_STAT_INTERNAL;
		}

		crypto->crypto_outlen = l;

		signature = crypto->crypto_out;
		siglen = crypto->crypto_outlen;

		EVP_MD_CTX_free(md_ctx);

		break;
	  }
#endif /* USE_GNUTLS */

	  default:
		assert(0);
	}

	/* base64-encode the signature */
	dkim->dkim_b64siglen = siglen * 3 + 5;
	dkim->dkim_b64siglen += (dkim->dkim_b64siglen / 60);
	dkim->dkim_b64sig = DKIM_MALLOC(dkim, dkim->dkim_b64siglen);
	if (dkim->dkim_b64sig == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           dkim->dkim_b64siglen);
#ifndef USE_GNUTLS
		BIO_free(crypto->crypto_keydata);
#endif /* ! USE_GNUTLS */
		return DKIM_STAT_NORESOURCE;
	}
	memset(dkim->dkim_b64sig, '\0', dkim->dkim_b64siglen);

	status = dkim_base64_encode(signature, siglen, dkim->dkim_b64sig,
	                            dkim->dkim_b64siglen);

#ifndef USE_GNUTLS
	BIO_free(crypto->crypto_keydata);
#endif /* ! USE_GNUTLS */

	if (status == -1)
	{
		dkim_error(dkim,
		           "base64 encoding error (buffer too small)");
		return DKIM_STAT_NORESOURCE;
	}

	dkim->dkim_signature = sig;

	return DKIM_STAT_OK;
}

/*
**  DKIM_EOM_VERIFY -- declare end-of-body; complete verification
**
**  Parameters:
**  	dkim -- DKIM handle
**  	testkey -- TRUE iff the a matching key was found but is marked as a
**  	           test key (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

static DKIM_STAT
dkim_eom_verify(DKIM *dkim, _Bool *testkey)
{
	DKIM_STAT ret;
	int c;
	int status;
	DKIM_SIGINFO *sig = NULL;
	struct dkim_header *hdr;
	DKIM_LIB *lib;

	assert(dkim != NULL);

	if (dkim->dkim_state >= DKIM_STATE_EOM2 ||
	    dkim->dkim_state < DKIM_STATE_EOH1)
		return DKIM_STAT_INVALID;
	if (dkim->dkim_state < DKIM_STATE_EOM1)
		dkim->dkim_state = DKIM_STATE_EOM1;

	if (dkim->dkim_chunkstate != DKIM_CHUNKSTATE_INIT &&
	    dkim->dkim_chunkstate != DKIM_CHUNKSTATE_DONE)
		return DKIM_STAT_INVALID;

	/* finalize body canonicalizations */
	ret = dkim_canon_closebody(dkim);
	if (ret != DKIM_STAT_OK)
		return ret;

	dkim->dkim_bodydone = TRUE;

	if (dkim->dkim_sigcount == 0)
	{					/* unsigned */
		if (dkim->dkim_domain == NULL)
		{
			u_char *domain;
			u_char *user;

			hdr = dkim_get_header(dkim, (u_char *) DKIM_FROMHEADER,
			                      DKIM_FROMHEADER_LEN, 0);
			if (hdr == NULL)
			{
				dkim_error(dkim, "no %s header found",
				           DKIM_FROMHEADER);
				return DKIM_STAT_CANTVRFY;
			}

			if (hdr->hdr_colon == NULL)
			{
				dkim_error(dkim, "%s header malformed",
				           DKIM_FROMHEADER);
				return DKIM_STAT_CANTVRFY;
			}

			status = dkim_mail_parse(hdr->hdr_colon + 1,
			                         &user, &domain);
			if (status != 0 || domain == NULL || domain[0] == '\0')
			{
				dkim_error(dkim, "%s header malformed",
				           DKIM_FROMHEADER);
				return DKIM_STAT_CANTVRFY;
			}

			dkim->dkim_domain = dkim_strdup(dkim, domain, 0);
			if (dkim->dkim_domain == NULL)
				return DKIM_STAT_NORESOURCE;
		}

		dkim->dkim_state = DKIM_STATE_EOM2;

		return DKIM_STAT_NOSIG;
	}

	lib = dkim->dkim_libhandle;

	/*
	**  If a signature has "l=" set but it was greater than the
	**  canonicalized body length, the signature is invalid.
	*/

	for (c = 0; c < dkim->dkim_sigcount; c++)
	{
		sig = dkim->dkim_siglist[c];

		if (sig->sig_bodycanon != NULL &&
		    sig->sig_bodycanon->canon_length != (ssize_t) -1 &&
		    sig->sig_bodycanon->canon_wrote < sig->sig_bodycanon->canon_length)
			sig->sig_error = DKIM_SIGERROR_TOOLARGE_L;
	}

	/* invoke the final callback if defined */
	if (lib->dkiml_final != NULL)
	{
		status = lib->dkiml_final(dkim, dkim->dkim_siglist,
		                          dkim->dkim_sigcount);
		switch (status)
		{
		  case DKIM_CBSTAT_CONTINUE:
		  case DKIM_CBSTAT_DEFAULT:
			break;

		  case DKIM_CBSTAT_REJECT:
			return DKIM_STAT_CBREJECT;

		  case DKIM_CBSTAT_TRYAGAIN:
			return DKIM_STAT_CBTRYAGAIN;

		  case DKIM_CBSTAT_ERROR:
			return DKIM_STAT_CBERROR;

		  default:
			return DKIM_STAT_CBINVALID;
		}
	}

	dkim->dkim_state = DKIM_STATE_EOM2;

	/* see if we have a passing signature with bh match */
	for (c = 0; c < dkim->dkim_sigcount; c++)
	{
		sig = dkim->dkim_siglist[c];

		if ((sig->sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
		    (sig->sig_flags & DKIM_SIGFLAG_IGNORE) == 0 &&
		    sig->sig_bh == DKIM_SIGBH_MATCH)
			break;

		sig = NULL;
	}

	/* run 'em until we get one */
	if (sig == NULL)
	{
		DKIM_SIGINFO *firstgood = NULL;

		for (c = 0; c < dkim->dkim_sigcount; c++)
		{
			sig = dkim->dkim_siglist[c];

			/* if not ignoring */
			if ((sig->sig_flags & DKIM_SIGFLAG_IGNORE) == 0)
			{
				/* run this signature */
				status = dkim_sig_process(dkim, sig);
				if (status != DKIM_STAT_OK)
				{
					sig = NULL;
					continue;
				}

				/*
				**  If the signature has fewer than the
				**  minimum number of key bits required by
				**  configuration, the signature is invalid.
				*/

				if (sig->sig_error == 0 &&
				    sig->sig_signalg != DKIM_SIGN_ED25519SHA256 &&
				    sig->sig_keybits < lib->dkiml_minkeybits)
				{
					sig->sig_error = DKIM_SIGERROR_KEYTOOSMALL;
					sig->sig_flags &= ~DKIM_SIGFLAG_PASSED;
				}

				/* pass and bh match? */
				if ((sig->sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
				    sig->sig_bh == DKIM_SIGBH_MATCH)
				{
					if (firstgood == NULL)
						firstgood = sig;

					/* continue? */
					if ((lib->dkiml_flags & DKIM_LIBFLAGS_VERIFYONE) != 0)
						break;
				}
			}

			sig = NULL;
		}

		if (sig == NULL)
			sig = firstgood;
	}

	/*
	**  If still none, we're going to fail so just use the first one.
	*/

	if (sig == NULL)
	{
		for (c = 0; c < dkim->dkim_sigcount; c++)
		{
			sig = dkim->dkim_siglist[c];
			if ((sig->sig_flags & DKIM_SIGFLAG_IGNORE) == 0)
				break;
			sig = NULL;
		}
	}

	/* caller marked everything with "ignore" */
	if (sig == NULL)
	{
		dkim_error(dkim, "all signatures ignored by caller");
		return DKIM_STAT_NOSIG;
	}

	dkim->dkim_signature = sig;

	/* things for which we return DKIM_STAT_CANTVRFY */
	if (sig->sig_error != DKIM_SIGERROR_OK &&
	    sig->sig_error != DKIM_SIGERROR_UNKNOWN &&
	    sig->sig_error != DKIM_SIGERROR_KEYFAIL &&
	    sig->sig_error != DKIM_SIGERROR_BADSIG &&
	    sig->sig_error != DKIM_SIGERROR_KEYREVOKED &&
	    sig->sig_error != DKIM_SIGERROR_NOKEY)
	{
		if (dkim->dkim_error == NULL ||
		    dkim->dkim_error[0] == '\0')
		{
			dkim_error(dkim, dkim_code_to_name(sigerrors,
			                                   sig->sig_error));
		}

		return DKIM_STAT_CANTVRFY;
	}

	/* initialize final result */
	ret = DKIM_STAT_OK;
	if (sig->sig_error == DKIM_SIGERROR_NOKEY)
		ret = DKIM_STAT_NOKEY;
	else if (sig->sig_error == DKIM_SIGERROR_KEYFAIL)
		ret = DKIM_STAT_KEYFAIL;
	else if (sig->sig_error == DKIM_SIGERROR_KEYREVOKED)
		ret = DKIM_STAT_REVOKED;
	else if ((sig->sig_flags & DKIM_SIGFLAG_PASSED) == 0)
		ret = DKIM_STAT_BADSIG;
	else if (sig->sig_bh == DKIM_SIGBH_MISMATCH)
		ret = DKIM_STAT_BADSIG;
	else if (sig->sig_error == DKIM_SIGERROR_BADSIG)
		ret = DKIM_STAT_BADSIG;

	/* set testkey based on the key flags */
	if (testkey != NULL &&
	    (sig->sig_flags & DKIM_SIGFLAG_TESTKEY) != 0)
		*testkey = TRUE;

	return ret;
}

/*
**  DKIM_NEW -- allocate a new message context
**
**  Parameters:
**  	libhandle -- DKIM_LIB handle
**  	id -- transaction ID string
**  	memclosure -- memory closure
**  	hdrcanon_alg -- canonicalization algorithm to use for headers
**  	bodycanon_alg -- canonicalization algorithm to use for headers
**  	sign_alg -- signature algorithm to use
**  	statp -- status (returned)
**
**  Return value:
**  	A new DKIM handle, or NULL on failure.
*/

static DKIM *
dkim_new(DKIM_LIB *libhandle, const unsigned char *id, void *memclosure,
         dkim_canon_t hdrcanon_alg, dkim_canon_t bodycanon_alg,
         dkim_alg_t sign_alg, DKIM_STAT *statp)
{
	DKIM *new;

	assert(libhandle != NULL);

	/* allocate the handle */
	new = (DKIM *) dkim_malloc(libhandle, memclosure,
	                           sizeof(struct dkim));
	if (new == NULL)
	{
		*statp = DKIM_STAT_NORESOURCE;
		return NULL;
	}

	/* populate defaults */
	memset(new, '\0', sizeof(struct dkim));
	new->dkim_id = id;
	new->dkim_signalg = (sign_alg == -1 ? DKIM_SIGN_DEFAULT
	                                    : sign_alg);
	new->dkim_hdrcanonalg = (hdrcanon_alg == -1 ? DKIM_CANON_DEFAULT
	                                            : hdrcanon_alg);
	new->dkim_bodycanonalg = (bodycanon_alg == -1 ? DKIM_CANON_DEFAULT
	                                              : bodycanon_alg);
	new->dkim_querymethods = NULL;
	new->dkim_mode = DKIM_MODE_UNKNOWN;
	new->dkim_chunkcrlf = DKIM_CRLF_UNKNOWN;
	new->dkim_state = DKIM_STATE_INIT;
	new->dkim_margin = (size_t) DKIM_HDRMARGIN;
	new->dkim_closure = memclosure;
	new->dkim_libhandle = libhandle;
	new->dkim_tmpdir = libhandle->dkiml_tmpdir;
	new->dkim_timeout = libhandle->dkiml_timeout;

	*statp = DKIM_STAT_OK;

#ifdef QUERY_CACHE
	if ((libhandle->dkiml_flags & DKIM_LIBFLAGS_CACHE) != 0 &&
	    libhandle->dkiml_cache == NULL)
	{
		int err = 0;

		libhandle->dkiml_cache = dkim_cache_init(&err,
		                                         libhandle->dkiml_tmpdir);
	}
#endif /* QUERY_CACHE */

	return new;
}

#ifndef USE_GNUTLS
/*
**  DKIM_INIT_OPENSSL -- initialize OpenSSL algorithms if needed
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

static pthread_mutex_t openssl_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned openssl_refcount = 0;

static void
dkim_init_openssl(void)
{
	pthread_mutex_lock(&openssl_lock);

	if (openssl_refcount == 0)
		OpenSSL_add_all_algorithms();
	openssl_refcount++;

	pthread_mutex_unlock(&openssl_lock);
}

/*
**  DKIM_CLOSE_OPENSSL -- clean up OpenSSL algorithms if needed
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

static void
dkim_close_openssl(void)
{
	assert(openssl_refcount > 0);

	pthread_mutex_lock(&openssl_lock);

	openssl_refcount--;
	if (openssl_refcount == 0)
		EVP_cleanup();

	pthread_mutex_unlock(&openssl_lock);
}
#endif /* ! USE_GNUTLS */

/* ========================= PUBLIC SECTION ========================== */

/*
**  DKIM_INIT -- initialize a DKIM library context
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**
**  Return value:
**  	A new DKIM_LIB handle suitable for use with other DKIM functions, or
**  	NULL on failure.
**
**  Side effects:
**  	Crop circles near Birmingham.
*/

DKIM_LIB *
dkim_init(void *(*caller_mallocf)(void *closure, size_t nbytes),
          void (*caller_freef)(void *closure, void *p))
{
	u_char *td;
	DKIM_LIB *libhandle;

#ifndef USE_GNUTLS
	/* initialize OpenSSL algorithms */
	dkim_init_openssl();
#endif /* USE_GNUTLS */

	/* copy the parameters */
	libhandle = (DKIM_LIB *) malloc(sizeof(struct dkim_lib));
	if (libhandle == NULL)
		return NULL;

	td = (u_char *) getenv("DKIM_TMPDIR");
	if (td == NULL || td[0] == '\0')
		td = (u_char *) DEFTMPDIR;

	libhandle->dkiml_signre = FALSE;
	libhandle->dkiml_skipre = FALSE;
	libhandle->dkiml_malloc = caller_mallocf;
	libhandle->dkiml_free = caller_freef;
	strlcpy((char *) libhandle->dkiml_tmpdir, (char *) td, 
	        sizeof libhandle->dkiml_tmpdir);
	libhandle->dkiml_flags = DKIM_LIBFLAGS_DEFAULT;
	libhandle->dkiml_timeout = DEFTIMEOUT;
	libhandle->dkiml_requiredhdrs = (u_char **) dkim_required_signhdrs;
	libhandle->dkiml_oversignhdrs = NULL;
	libhandle->dkiml_mbs = NULL;
	libhandle->dkiml_querymethod = DKIM_QUERY_UNKNOWN;
	memset(libhandle->dkiml_queryinfo, '\0',
	       sizeof libhandle->dkiml_queryinfo);
#ifdef QUERY_CACHE
	libhandle->dkiml_cache = NULL;
#endif /* QUERY_CACHE */
	libhandle->dkiml_fixedtime = 0;
	libhandle->dkiml_sigttl = 0;
	libhandle->dkiml_clockdrift = DEFCLOCKDRIFT;
	libhandle->dkiml_minkeybits = DEFMINKEYBITS;

	libhandle->dkiml_key_lookup = NULL;
	libhandle->dkiml_sig_handle = NULL;
	libhandle->dkiml_sig_handle_free = NULL;
	libhandle->dkiml_sig_tagvalues = NULL;
	libhandle->dkiml_prescreen = NULL;
	libhandle->dkiml_final = NULL;
	libhandle->dkiml_dns_callback = NULL;
	libhandle->dkiml_dns_service = NULL;
	libhandle->dkiml_dnsinit_done = FALSE;
	libhandle->dkiml_dns_init = dkim_res_init;
	libhandle->dkiml_dns_close = dkim_res_close;
	libhandle->dkiml_dns_start = dkim_res_query;
	libhandle->dkiml_dns_cancel = dkim_res_cancel;
	libhandle->dkiml_dns_waitreply = dkim_res_waitreply;
	
#define FEATURE_INDEX(x)	((x) / (8 * sizeof(u_int)))
#define FEATURE_OFFSET(x)	((x) % (8 * sizeof(u_int)))
#define FEATURE_ADD(lib,x)	(lib)->dkiml_flist[FEATURE_INDEX((x))] |= (1 << FEATURE_OFFSET(x))

	libhandle->dkiml_flsize = (FEATURE_INDEX(DKIM_FEATURE_MAX)) + 1;
	libhandle->dkiml_flist = (u_int *) malloc(sizeof(u_int) * libhandle->dkiml_flsize);
	if (libhandle->dkiml_flist == NULL)
	{
		free(libhandle);
		return NULL;
	}
	memset(libhandle->dkiml_flist, '\0',
	       sizeof(u_int) * libhandle->dkiml_flsize);

#ifdef _FFR_DIFFHEADERS
	FEATURE_ADD(libhandle, DKIM_FEATURE_DIFFHEADERS);
#endif /* _FFR_DIFFHEADERS */
#ifdef QUERY_CACHE
	FEATURE_ADD(libhandle, DKIM_FEATURE_QUERY_CACHE);
#endif /* QUERY_CACHE */
#ifdef HAVE_SHA256
	FEATURE_ADD(libhandle, DKIM_FEATURE_SHA256);
#endif /* HAVE_SHA256 */
#ifdef HAVE_ED25519
	FEATURE_ADD(libhandle, DKIM_FEATURE_ED25519);
#endif /* HAVE_ED25519 */
#ifdef _FFR_DNSSEC
	FEATURE_ADD(libhandle, DKIM_FEATURE_DNSSEC);
#endif /* _FFR_DNSSEC */
#ifdef _FFR_RESIGN
	FEATURE_ADD(libhandle, DKIM_FEATURE_RESIGN);
#endif /* _FFR_RESIGN */
#ifdef _FFR_ATPS
	FEATURE_ADD(libhandle, DKIM_FEATURE_ATPS);
#endif /* _FFR_ATPS */
	FEATURE_ADD(libhandle, DKIM_FEATURE_OVERSIGN);
	FEATURE_ADD(libhandle, DKIM_FEATURE_XTAGS);
#ifdef _FFR_CONDITIONAL
	FEATURE_ADD(libhandle, DKIM_FEATURE_CONDITIONAL);
#endif /* _FFR_CONDITIONAL */

	/* initialize the resolver */
	(void) res_init();

	return libhandle;
}

/*
**  DKIM_CLOSE -- shut down a DKIM library package
**
**  Parameters:
**  	lib -- library handle to shut down
**
**  Return value:
**  	None.
*/

void
dkim_close(DKIM_LIB *lib)
{
	assert(lib != NULL);

#ifdef QUERY_CACHE
	if (lib->dkiml_cache != NULL)
		(void) dkim_cache_close(lib->dkiml_cache);
#endif /* QUERY_CACHE */

	if (lib->dkiml_skipre)
		(void) regfree(&lib->dkiml_skiphdrre);
	
	if (lib->dkiml_signre)
		(void) regfree(&lib->dkiml_hdrre);

	if (lib->dkiml_oversignhdrs != NULL)
		dkim_clobber_array((char **) lib->dkiml_oversignhdrs);

	if (lib->dkiml_requiredhdrs != (u_char **) dkim_required_signhdrs)
		dkim_clobber_array((char **) lib->dkiml_requiredhdrs);

	if (lib->dkiml_mbs != NULL)
		dkim_clobber_array((char **) lib->dkiml_mbs);

	free(lib->dkiml_flist);

	if (lib->dkiml_dns_close != NULL && lib->dkiml_dns_service != NULL)
		lib->dkiml_dns_close(lib->dkiml_dns_service);
	
	free((void *) lib);

#ifndef USE_GNUTLS
	dkim_close_openssl();
#endif /* ! USE_GNUTLS */
}

/*
**  DKIM_ERROR -- log an error into a DKIM handle
**
**  Parameters:
**  	dkim -- DKIM context in which this is performed
**  	format -- format to apply
**  	... -- arguments
**
**  Return value:
**  	None.
*/

void
dkim_error(DKIM *dkim, const char *format, ...)
{
	int flen;
	int saverr;
	u_char *new;
	va_list va;

	assert(dkim != NULL);
	assert(format != NULL);

	saverr = errno;

	if (dkim->dkim_error == NULL)
	{
		dkim->dkim_error = DKIM_MALLOC(dkim, DEFERRLEN);
		if (dkim->dkim_error == NULL)
		{
			errno = saverr;
			return;
		}
		dkim->dkim_errlen = DEFERRLEN;
	}

	for (;;)
	{
		va_start(va, format);
		flen = vsnprintf((char *) dkim->dkim_error, dkim->dkim_errlen,
		                 format, va);
		va_end(va);

		/* compensate for broken vsnprintf() implementations */
		if (flen == -1)
			flen = dkim->dkim_errlen * 2;

		if (flen >= dkim->dkim_errlen)
		{
			new = DKIM_MALLOC(dkim, flen + 1);
			if (new == NULL)
			{
				errno = saverr;
				return;
			}

			DKIM_FREE(dkim, dkim->dkim_error);
			dkim->dkim_error = new;
			dkim->dkim_errlen = flen + 1;
		}
		else
		{
			break;
		}
	}

	errno = saverr;
}

/*
**  DKIM_OPTIONS -- get or set a library option
**
**  Parameters:
**  	lib -- DKIM library handle
**  	op -- operation to perform
**  	opt -- option to get/set
**  	ptr -- pointer to its old/new value
**  	len -- memory available at "ptr"
**
**  Return value:
**  	A DKIM_STAT constant.
*/

DKIM_STAT
dkim_options(DKIM_LIB *lib, int op, dkim_opts_t opt, void *ptr, size_t len)
{
	assert(lib != NULL);
	assert(op == DKIM_OP_SETOPT || op == DKIM_OP_GETOPT);
	assert(len != 0);

	switch (opt)
	{
	  case DKIM_OPTS_TMPDIR:
		if (op == DKIM_OP_GETOPT)
		{
			strlcpy((char *) ptr, (char *) lib->dkiml_tmpdir, len);
		}
		else if (ptr == NULL)
		{
			strlcpy((char *) lib->dkiml_tmpdir, DEFTMPDIR,
			        sizeof lib->dkiml_tmpdir);
		}
		else
		{
			strlcpy((char *) lib->dkiml_tmpdir, (char *) ptr,
			        sizeof lib->dkiml_tmpdir);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_FIXEDTIME:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_fixedtime)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
			memcpy(ptr, &lib->dkiml_fixedtime, len);
		else
			memcpy(&lib->dkiml_fixedtime, ptr, len);

		return DKIM_STAT_OK;

	  case DKIM_OPTS_MINKEYBITS:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_minkeybits)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
			memcpy(ptr, &lib->dkiml_minkeybits, len);
		else
			memcpy(&lib->dkiml_minkeybits, ptr, len);

		return DKIM_STAT_OK;

	  case DKIM_OPTS_SIGNATURETTL:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_sigttl)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
			memcpy(ptr, &lib->dkiml_sigttl, len);
		else
			memcpy(&lib->dkiml_sigttl, ptr, len);

		return DKIM_STAT_OK;

	  case DKIM_OPTS_CLOCKDRIFT:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_clockdrift)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
			memcpy(ptr, &lib->dkiml_clockdrift, len);
		else
			memcpy(&lib->dkiml_clockdrift, ptr, len);

		return DKIM_STAT_OK;

	  case DKIM_OPTS_FLAGS:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_flags)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
			memcpy(ptr, &lib->dkiml_flags, len);
		else
			memcpy(&lib->dkiml_flags, ptr, len);

		return DKIM_STAT_OK;

	  case DKIM_OPTS_TIMEOUT:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_timeout)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
			memcpy(ptr, &lib->dkiml_timeout, len);
		else
			memcpy(&lib->dkiml_timeout, ptr, len);

		return DKIM_STAT_OK;

	  case DKIM_OPTS_REQUIREDHDRS:
		if (len != sizeof lib->dkiml_requiredhdrs)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_requiredhdrs, len);
		}
		else if (ptr == NULL)
		{
			if (lib->dkiml_requiredhdrs != (u_char **) dkim_required_signhdrs)
				dkim_clobber_array((char **) lib->dkiml_requiredhdrs);

			lib->dkiml_requiredhdrs = (u_char **) dkim_required_signhdrs;
		}
		else
		{
			const char **tmp;

			tmp = dkim_copy_array(ptr);
			if (tmp == NULL)
				return DKIM_STAT_NORESOURCE;

			if (lib->dkiml_requiredhdrs != (u_char **) dkim_required_signhdrs)
				dkim_clobber_array((char **) lib->dkiml_requiredhdrs);

			lib->dkiml_requiredhdrs = (u_char **) tmp;
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_OVERSIGNHDRS:
		if (len != sizeof lib->dkiml_oversignhdrs)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_oversignhdrs, len);
		}
		else if (ptr == NULL)
		{
			if (lib->dkiml_oversignhdrs != NULL)
				dkim_clobber_array((char **) lib->dkiml_oversignhdrs);
			lib->dkiml_oversignhdrs = NULL;
		}
		else
		{
			const char **tmp;

			tmp = dkim_copy_array(ptr);
			if (tmp == NULL)
				return DKIM_STAT_NORESOURCE;

			if (lib->dkiml_oversignhdrs != NULL)
				dkim_clobber_array((char **) lib->dkiml_oversignhdrs);

			lib->dkiml_oversignhdrs = (u_char **) tmp;
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_MUSTBESIGNED:
		if (len != sizeof lib->dkiml_mbs)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_mbs, len);
		}
		else if (ptr == NULL)
		{
			if (lib->dkiml_mbs != NULL)
				dkim_clobber_array((char **) lib->dkiml_mbs);

			lib->dkiml_mbs = NULL;
		}
		else
		{
			const char **tmp;

			tmp = dkim_copy_array(ptr);
			if (tmp == NULL)
				return DKIM_STAT_NORESOURCE;

			if (lib->dkiml_mbs != NULL)
				dkim_clobber_array((char **) lib->dkiml_mbs);

			lib->dkiml_mbs = (u_char **) tmp;
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_SIGNHDRS:
		if (len != sizeof(char **) || op == DKIM_OP_GETOPT)
		{
			return DKIM_STAT_INVALID;
		}
		else if (ptr == NULL)
		{
			if (lib->dkiml_signre)
			{
				(void) regfree(&lib->dkiml_hdrre);
				lib->dkiml_signre = FALSE;
			}
		}
		else
		{
			int status;
			u_char **hdrs;
			u_char **required_signhdrs;
			char buf[BUFRSZ + 1];

			if (lib->dkiml_signre)
			{
				(void) regfree(&lib->dkiml_hdrre);
				lib->dkiml_signre = FALSE;
			}

			memset(buf, '\0', sizeof buf);

			hdrs = (u_char **) ptr;

			(void) strlcpy(buf, "^(", sizeof buf);

			required_signhdrs = lib->dkiml_requiredhdrs;
			if (!dkim_hdrlist((u_char *) buf, sizeof buf,
			                  (u_char **) required_signhdrs, TRUE))
				return DKIM_STAT_INVALID;
			if (!dkim_hdrlist((u_char *) buf, sizeof buf,
			                  hdrs, FALSE))
				return DKIM_STAT_INVALID;

			if (strlcat(buf, ")$", sizeof buf) >= sizeof buf)
				return DKIM_STAT_INVALID;

			status = regcomp(&lib->dkiml_hdrre, buf,
			                 (REG_EXTENDED|REG_ICASE));
			if (status != 0)
				return DKIM_STAT_INTERNAL;

			lib->dkiml_signre = TRUE;
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_SKIPHDRS:
		if (len != sizeof(char **) || op == DKIM_OP_GETOPT)
		{
			return DKIM_STAT_INVALID;
		}
		else if (ptr == NULL)
		{
			if (lib->dkiml_skipre)
			{
				(void) regfree(&lib->dkiml_skiphdrre);
				lib->dkiml_skipre = FALSE;
			}
		}
		else
		{
			int status;
			u_char **hdrs;
			char buf[BUFRSZ + 1];

			if (lib->dkiml_skipre)
			{
				(void) regfree(&lib->dkiml_skiphdrre);
				lib->dkiml_skipre = FALSE;
			}

			memset(buf, '\0', sizeof buf);

			hdrs = (u_char **) ptr;

			(void) strlcpy(buf, "^(", sizeof buf);

			if (!dkim_hdrlist((u_char *) buf, sizeof buf,
			                  hdrs, TRUE))
				return DKIM_STAT_INVALID;

			if (strlcat(buf, ")$", sizeof buf) >= sizeof buf)
				return DKIM_STAT_INVALID;

			status = regcomp(&lib->dkiml_skiphdrre, buf,
			                 (REG_EXTENDED|REG_ICASE));
			if (status != 0)
				return DKIM_STAT_INTERNAL;

			lib->dkiml_skipre = TRUE;
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_QUERYMETHOD:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_querymethod)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
			memcpy(ptr, &lib->dkiml_querymethod, len);
		else
			memcpy(&lib->dkiml_querymethod, ptr, len);

		return DKIM_STAT_OK;

	  case DKIM_OPTS_QUERYINFO:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			strlcpy(ptr, (char *) lib->dkiml_queryinfo, len);
		}
		else
		{
			strlcpy((char *) lib->dkiml_queryinfo, ptr,
			        sizeof lib->dkiml_queryinfo);
		}
		return DKIM_STAT_OK;

	  default:
		return DKIM_STAT_INVALID;
	}
}

/*
**  DKIM_FREE -- destroy a DKIM handle
**
**  Parameters:
**  	dkim -- DKIM handle to destroy
**
**  Return value:
**  	A DKIM_STAT constant.
*/

DKIM_STAT
dkim_free(DKIM *dkim)
{
	assert(dkim != NULL);

#ifdef _FFR_RESIGN
	/* XXX -- this should be mutex-protected */
	if (dkim->dkim_resign != NULL)
	{
		if (dkim->dkim_resign->dkim_refcnt == 0)
			dkim_free(dkim->dkim_resign);
		else
			dkim->dkim_resign->dkim_refcnt--;
	}
	else if (dkim->dkim_refcnt != 0)
	{
		return DKIM_STAT_INVALID;
	}
#endif /* _FFR_RESIGN */

	/* blast the headers */
#ifdef _FFR_RESIGN
	if (dkim->dkim_resign == NULL && dkim->dkim_hhead != NULL)
#else /* _FFR_RESIGN */
	if (dkim->dkim_hhead != NULL)
#endif /* _FFR_RESIGN */
	{
		struct dkim_header *next;
		struct dkim_header *hdr;

		for (hdr = dkim->dkim_hhead; hdr != NULL; )
		{
			next = hdr->hdr_next;

			CLOBBER(hdr->hdr_text);
			CLOBBER(hdr);

			hdr = next;
		}
	}

	/* blast the data sets */
#ifdef _FFR_RESIGN
	if (dkim->dkim_resign == NULL && dkim->dkim_sethead != NULL)
#else /* _FFR_RESIGN */
	if (dkim->dkim_sethead != NULL)
#endif /* _FFR_RESIGN */
	{
		DKIM_SET *set;
		DKIM_SET *next;

		for (set = dkim->dkim_sethead; set != NULL; )
		{
			next = set->set_next;

			dkim_set_free(dkim, set);

			set = next;
		}
	}

	/* trash the signature list */
	if (dkim->dkim_siglist != NULL)
	{
		int c;

		for (c = 0; c < dkim->dkim_sigcount; c++)
		{
			if (dkim->dkim_siglist[c]->sig_context != NULL &&
			    dkim->dkim_libhandle->dkiml_sig_handle_free != NULL)
			{
				dkim->dkim_libhandle->dkiml_sig_handle_free(dkim->dkim_closure,
				                                            dkim->dkim_siglist[c]->sig_context);
			}

			if (dkim->dkim_siglist[c]->sig_sslerrbuf != NULL)
				dkim_dstring_free(dkim->dkim_siglist[c]->sig_sslerrbuf);

			CLOBBER(dkim->dkim_siglist[c]->sig_key);
			CLOBBER(dkim->dkim_siglist[c]->sig_sig);
			if (dkim->dkim_siglist[c]->sig_keytype == DKIM_KEYTYPE_RSA)
			{
				struct dkim_crypto *crypto;

				crypto = dkim->dkim_siglist[c]->sig_signature;
				if (crypto != NULL)
				{
#ifdef USE_GNUTLS
					KEY_CLOBBER(crypto->crypto_key);
					PUBKEY_CLOBBER(crypto->crypto_pubkey);
					PRIVKEY_CLOBBER(crypto->crypto_privkey);
					HCLOBBER(crypto->crypto_rsaout.data);
#else /* USE_GNUTLS */
					BIO_CLOBBER(crypto->crypto_keydata);
					EVP_CLOBBER(crypto->crypto_pkey);
					RSA_CLOBBER(crypto->crypto_key);
					CLOBBER(crypto->crypto_out);
#endif /* USE_GNUTLS */
				}
			}
			CLOBBER(dkim->dkim_siglist[c]->sig_signature);
			CLOBBER(dkim->dkim_siglist[c]);
		}

		CLOBBER(dkim->dkim_siglist);
	}

	if (dkim->dkim_querymethods != NULL)
	{
		struct dkim_qmethod *cur;
		struct dkim_qmethod *next;

		cur = dkim->dkim_querymethods;
		while (cur != NULL)
		{
			next = cur->qm_next;
			DKIM_FREE(dkim, cur->qm_type);
			if (cur->qm_options != NULL)
				DKIM_FREE(dkim, cur->qm_options);
			DKIM_FREE(dkim, cur);
			cur = next;
		}
	}

	if (dkim->dkim_xtags != NULL)
	{
		struct dkim_xtag *cur;
		struct dkim_xtag *next;

		cur = dkim->dkim_xtags;
		while (cur != NULL)
		{
			next = cur->xt_next;
			CLOBBER(cur->xt_tag);
			CLOBBER(cur->xt_value);
			free(cur);
			cur = next;
		}
	}

	if (dkim->dkim_hdrre != NULL)
	{
		regfree(dkim->dkim_hdrre);
		free(dkim->dkim_hdrre);
	}

	/* destroy canonicalizations */
	dkim_canon_cleanup(dkim);

	CLOBBER(dkim->dkim_b64sig);
	CLOBBER(dkim->dkim_selector);
	CLOBBER(dkim->dkim_domain);
	CLOBBER(dkim->dkim_user);
	CLOBBER(dkim->dkim_key);
	CLOBBER(dkim->dkim_sender);
	CLOBBER(dkim->dkim_signer);
	CLOBBER(dkim->dkim_error);
	CLOBBER(dkim->dkim_zdecode);
	CLOBBER(dkim->dkim_hdrlist);

	DSTRING_CLOBBER(dkim->dkim_hdrbuf);
	DSTRING_CLOBBER(dkim->dkim_canonbuf);
	DSTRING_CLOBBER(dkim->dkim_sslerrbuf);

	dkim_mfree(dkim->dkim_libhandle, dkim->dkim_closure, dkim);

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIGN -- allocate a handle for use in a signature operation
**
**  Parameters:
**  	libhandle -- DKIM_LIB handle
**  	id -- identification string (e.g. job ID) for logging
**  	memclosure -- memory closure for allocations (or NULL)
**  	secretkey -- secret key (PEM format)
**  	selector -- selector to be used when generating the signature header
**  	domain -- domain for which this message is being signed
**  	hdrcanonalg -- canonicalization algorithm to use for headers
**  	bodycanonalg -- canonicalization algorithm to use for body
**  	signalg -- signing algorithm to use
**  	length -- how many bytes of the body to sign (-1 for all)
**  	statp -- status (returned)
**
**  Return value:
**  	A new signing handle, or NULL.
*/

DKIM *
dkim_sign(DKIM_LIB *libhandle, const unsigned char *id, void *memclosure,
          const dkim_sigkey_t secretkey, const unsigned char *selector,
          const unsigned char *domain, dkim_canon_t hdrcanonalg,
	  dkim_canon_t bodycanonalg, dkim_alg_t signalg,
          ssize_t length, DKIM_STAT *statp)
{
	unsigned char *p;
	DKIM *new;

	assert(libhandle != NULL);
	assert(secretkey != NULL);
	assert(selector != NULL);
	assert(domain != NULL);
	assert(hdrcanonalg == DKIM_CANON_SIMPLE ||
	       hdrcanonalg == DKIM_CANON_RELAXED);
	assert(bodycanonalg == DKIM_CANON_SIMPLE ||
	       bodycanonalg == DKIM_CANON_RELAXED);
	assert(signalg == DKIM_SIGN_DEFAULT ||
	       signalg == DKIM_SIGN_RSASHA1 ||
               signalg == DKIM_SIGN_RSASHA256 ||
               signalg == DKIM_SIGN_ED25519SHA256);
	assert(statp != NULL);

	if (dkim_libfeature(libhandle, DKIM_FEATURE_SHA256))
	{
		if (signalg == DKIM_SIGN_DEFAULT)
			signalg = DKIM_SIGN_RSASHA256;
	}
	else
	{
		if (signalg == DKIM_SIGN_RSASHA256)
		{
			*statp = DKIM_STAT_INVALID;
			return NULL;
		}

		if (signalg == DKIM_SIGN_DEFAULT)
			signalg = DKIM_SIGN_RSASHA1;
	}

	if (!dkim_strisprint((u_char *) domain) ||
	    !dkim_strisprint((u_char *) selector))
	{
		*statp = DKIM_STAT_INVALID;
		return NULL;
	}

	new = dkim_new(libhandle, id, memclosure, hdrcanonalg, bodycanonalg,
	               signalg, statp);

	if (new != NULL)
	{
		new->dkim_mode = DKIM_MODE_SIGN;

		/* do DER decoding here if needed */
		if (strncmp((char *) secretkey, "MII", 3) == 0)
		{
			size_t b64len;

			b64len = strlen((char *) secretkey);

			new->dkim_key = (unsigned char *) DKIM_MALLOC(new,
			                                              b64len);
			if (new->dkim_key == NULL)
			{
				*statp = DKIM_STAT_NORESOURCE;
				dkim_free(new);
				return NULL;
			}

			new->dkim_keylen = dkim_base64_decode(secretkey,
			                                      new->dkim_key,
			                                      b64len);
			if (new->dkim_keylen <= 0)
			{
				*statp = DKIM_STAT_NORESOURCE;
				dkim_free(new);
				return NULL;
			}
		}
		else
		{
			new->dkim_keylen = strlen((const char *) secretkey);
			new->dkim_key = dkim_strdup(new, secretkey, 0);

			if (new->dkim_key == NULL)
			{
				*statp = DKIM_STAT_NORESOURCE;
				dkim_free(new);
				return NULL;
			}
		}

		new->dkim_selector = dkim_strdup(new, selector, 0);
		new->dkim_domain = dkim_strdup(new, domain, 0);
		if (length == (ssize_t) -1)
		{
			new->dkim_signlen = ULONG_MAX;
		}
		else
		{
			new->dkim_signlen = length;
			new->dkim_partial = TRUE;
		}
	}

	return new;
}

/*
**  DKIM_VERIFY -- allocate a handle for use in a verify operation
**
**  Parameters:
**  	libhandle -- DKIM_LIB handle
**  	id -- identification string (e.g. job ID) for logging
**  	memclosure -- memory closure for allocations (or NULL)
**  	statp -- status (returned)
**
**  Return value:
**  	A new signing handle, or NULL.
*/

DKIM *
dkim_verify(DKIM_LIB *libhandle, const unsigned char *id, void *memclosure,
            DKIM_STAT *statp)
{
	DKIM *new;

	assert(libhandle != NULL);
	assert(statp != NULL);

	new = dkim_new(libhandle, id, memclosure, DKIM_CANON_UNKNOWN,
	               DKIM_CANON_UNKNOWN, DKIM_SIGN_UNKNOWN, statp);

	if (new != NULL)
		new->dkim_mode = DKIM_MODE_VERIFY;

	return new;
}

/*
**  DKIM_RESIGN -- bind a new signing handle to a completed handle
**
**  Parameters:
**  	new -- new signing handle
**  	old -- old signing/verifying handle
**  	hdrbind -- bind "new"'s header canonicalization to "old" as well
**  	           as the body
**
**  Return value:
**  	DKIM_STAT_OK -- success
**  	DKIM_STAT_INVALID -- invalid state of one or both handles
**
**  Side effects:
**  	Sets up flags such that the two are bound; dkim_free() on "old"
**  	is now an invalid operation until "new" has been free'd.
*/

DKIM_STAT
dkim_resign(DKIM *new, DKIM *old, _Bool hdrbind)
{
#ifdef _FFR_RESIGN
	_Bool keep;
	_Bool tmp;
	DKIM_STAT status;
	int hashtype = DKIM_HASHTYPE_UNKNOWN;
	DKIM_CANON *bc;
	DKIM_CANON *hc;
	DKIM_LIB *lib;

	assert(new != NULL);
	assert(old != NULL);

	if (new->dkim_mode != DKIM_MODE_SIGN ||
	    new->dkim_state != DKIM_STATE_INIT)
		return DKIM_STAT_INVALID;

	if (old->dkim_state >= DKIM_STATE_EOH1 ||
	    old->dkim_resign != NULL)
		return DKIM_STAT_INVALID;

	new->dkim_resign = old;
	new->dkim_hdrbind = hdrbind;
	/* XXX -- should be mutex-protected? */
	old->dkim_refcnt++;

	if (new->dkim_hdrbind)
	{
		new->dkim_hhead = old->dkim_hhead;
		new->dkim_hdrcnt = old->dkim_hdrcnt;
	}

	lib = old->dkim_libhandle;
	assert(lib != NULL);

	tmp = ((lib->dkiml_flags & DKIM_LIBFLAGS_TMPFILES) != 0);
	keep = ((lib->dkiml_flags & DKIM_LIBFLAGS_KEEPFILES) != 0);

	new->dkim_version = lib->dkiml_version;

	/* determine hash type */
	switch (new->dkim_signalg)
	{
	  case DKIM_SIGN_RSASHA1:
		hashtype = DKIM_HASHTYPE_SHA1;
		break;

	  case DKIM_SIGN_RSASHA256:
		hashtype = DKIM_HASHTYPE_SHA256;
		break;

	  default:
		assert(0);
		/* NOTREACHED */
	}

	/* initialize signature and canonicalization for signing */
	new->dkim_siglist = DKIM_MALLOC(new, sizeof(DKIM_SIGINFO *));
	if (new->dkim_siglist == NULL)
	{
		dkim_error(new, "failed to allocate %d byte(s)",
		           sizeof(DKIM_SIGINFO *));
		return DKIM_STAT_NORESOURCE;
	}

	new->dkim_siglist[0] = DKIM_MALLOC(new, sizeof(struct dkim_siginfo));
	if (new->dkim_siglist[0] == NULL)
	{
		dkim_error(new, "failed to allocate %d byte(s)",
		           sizeof(struct dkim_siginfo));
		return DKIM_STAT_NORESOURCE;
	}

	new->dkim_sigcount = 1;
	memset(new->dkim_siglist[0], '\0', sizeof(struct dkim_siginfo));
	new->dkim_siglist[0]->sig_domain = new->dkim_domain;
	new->dkim_siglist[0]->sig_selector = new->dkim_selector;
	new->dkim_siglist[0]->sig_hashtype = hashtype;
	new->dkim_siglist[0]->sig_signalg = new->dkim_signalg;

	status = dkim_add_canon(new, TRUE, new->dkim_hdrcanonalg, hashtype,
	                        NULL, NULL, 0, &hc);
	if (status != DKIM_STAT_OK)
		return status;

	status = dkim_add_canon(old, FALSE, new->dkim_bodycanonalg,
	                        hashtype, NULL, NULL, new->dkim_signlen, &bc);
	if (status != DKIM_STAT_OK)
		return status;

	new->dkim_siglist[0]->sig_hdrcanon = hc;
	new->dkim_siglist[0]->sig_hdrcanonalg = new->dkim_hdrcanonalg;
	new->dkim_siglist[0]->sig_bodycanon = bc;
	new->dkim_siglist[0]->sig_bodycanonalg = new->dkim_bodycanonalg;

	if (new->dkim_libhandle->dkiml_fixedtime != 0)
	{
		new->dkim_siglist[0]->sig_timestamp = new->dkim_libhandle->dkiml_fixedtime;
	}
	else
	{
		time_t now;

		(void) time(&now);

		new->dkim_siglist[0]->sig_timestamp = (uint64_t) now;
	}

	if (new->dkim_hdrbind)
	{
		_Bool keep;

		keep = ((lib->dkiml_flags & DKIM_LIBFLAGS_KEEPFILES) != 0);

		/* initialize all canonicalizations */
		status = dkim_canon_init(new, tmp, keep);
		if (status != DKIM_STAT_OK)
			return status;

		/* run the headers */
		status = dkim_canon_runheaders(new);
		if (status != DKIM_STAT_OK)
			return status;
	}

	return DKIM_STAT_OK;
#else /* _FFR_RESIGN */
	return DKIM_STAT_NOTIMPLEMENT;
#endif /* _FFR_RESIGN */
}

/*
**  DKIM_SIG_PROCESS -- process a signature
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_process(DKIM *dkim, DKIM_SIGINFO *sig)
{
	DKIM_STAT status;
	int nid;
	int vstat;
	size_t diglen = 0;
#ifdef USE_GNUTLS
	gnutls_datum_t key;
#else /* USE_GNUTLS */
	BIO *key;
#endif /* USE_GNUTLS */
	u_char *digest = NULL;
	struct dkim_crypto *crypto;

	assert(dkim != NULL);
	assert(sig != NULL);

	/* skip it if we're supposed to ignore it */
	if ((sig->sig_flags & DKIM_SIGFLAG_IGNORE) != 0)
		return DKIM_STAT_OK;

	/* skip it if there was a syntax or other error */
	if (sig->sig_error != DKIM_SIGERROR_UNKNOWN)
		return DKIM_STAT_OK;

#ifdef _FFR_CONDITIONAL
	/* error out if we're recursing into conditional signatures too much */
	if (dkim->dkim_cddepth >= DKIM_MAXCDDEPTH)
	{
		dkim_error(dkim,
		           "too many levels of conditional signature indirection");
		sig->sig_error = DKIM_SIGERROR_CONDLOOP;
		return DKIM_STAT_CANTVRFY;
	}
#endif /* _FFR_CONDITIONAL */

	/* skip the DNS part if we've already done it */
	if ((sig->sig_flags & DKIM_SIGFLAG_PROCESSED) == 0)
	{
		/* get the digest */
		status = dkim_canon_getfinal(sig->sig_hdrcanon, &digest,
		                             &diglen);
		if (status != DKIM_STAT_OK)
		{
			dkim_error(dkim, "dkim_canon_getfinal() failed");
			return DKIM_STAT_INTERNAL;
		}
		assert(digest != NULL && diglen != 0);

		/* retrieve the key */
		status = dkim_get_key(dkim, sig, FALSE);
		if (status == DKIM_STAT_NOKEY)
		{
			sig->sig_flags |= DKIM_SIGFLAG_PROCESSED;
			sig->sig_error = DKIM_SIGERROR_NOKEY;
			return DKIM_STAT_OK;
		}
		else if (status == DKIM_STAT_KEYFAIL)
		{
			sig->sig_flags |= DKIM_SIGFLAG_PROCESSED;
			sig->sig_error = DKIM_SIGERROR_KEYFAIL;
			return DKIM_STAT_OK;
		}
		else if (status == DKIM_STAT_CANTVRFY ||
		         status == DKIM_STAT_SYNTAX)
		{
			sig->sig_flags |= DKIM_SIGFLAG_PROCESSED;
			if (sig->sig_error == DKIM_SIGERROR_UNKNOWN)
				sig->sig_error = DKIM_SIGERROR_DNSSYNTAX;
			return DKIM_STAT_OK;
		}
		else if (status == DKIM_STAT_MULTIDNSREPLY)
		{
			sig->sig_flags |= DKIM_SIGFLAG_PROCESSED;
			sig->sig_error = DKIM_SIGERROR_MULTIREPLY;
			return DKIM_STAT_OK;
		}
		else if (status == DKIM_STAT_REVOKED)
		{
			sig->sig_flags |= DKIM_SIGFLAG_PROCESSED;
			sig->sig_error = DKIM_SIGERROR_KEYREVOKED;
			return DKIM_STAT_OK;
		}
		else if (status != DKIM_STAT_OK)
		{
			return status;
		}

#ifdef USE_GNUTLS
		key.data = sig->sig_key;
		key.size = sig->sig_keylen;
#else /* USE_GNUTLS */
		/* load the public key */
		key = BIO_new_mem_buf(sig->sig_key, sig->sig_keylen);
		if (key == NULL)
		{
			dkim_error(dkim, "BIO_new_mem_buf() failed");
			return DKIM_STAT_NORESOURCE;
		}
#endif /* USE_GNUTLS */

		/* set up to verify */
		if (sig->sig_signature == NULL)
		{
			crypto = DKIM_MALLOC(dkim, sizeof(struct dkim_crypto));
			if (crypto == NULL)
			{
				dkim_error(dkim,
				           "unable to allocate %d byte(s)",
				           sizeof(struct dkim_crypto));
#ifndef USE_GNUTLS
				BIO_free(key);
#endif /* ! USE_GNUTLS */
				return DKIM_STAT_NORESOURCE;
			}

			sig->sig_signature = crypto;
		}
		else
		{
			crypto = sig->sig_signature;
		}
		memset(crypto, '\0', sizeof(struct dkim_crypto));

#ifdef USE_GNUTLS
		crypto->crypto_sig.data = sig->sig_sig;
		crypto->crypto_sig.size = sig->sig_siglen;

		crypto->crypto_digest.data = digest;
		crypto->crypto_digest.size = diglen;

		status = gnutls_pubkey_init(&crypto->crypto_pubkey);
		if (status != GNUTLS_E_SUCCESS)
		{
			dkim_sig_load_ssl_errors(dkim, sig, status);
			dkim_error(dkim,
			           "s=%s d=%s: gnutls_pubkey_init() failed",
			           dkim_sig_getselector(sig),
			           dkim_sig_getdomain(sig));

			sig->sig_error = DKIM_SIGERROR_KEYDECODE;

			return DKIM_STAT_OK;
		}

		status = gnutls_pubkey_import(crypto->crypto_pubkey, &key,
		                              GNUTLS_X509_FMT_DER);
		if (status != GNUTLS_E_SUCCESS)
		{
			dkim_sig_load_ssl_errors(dkim, sig, status);
			dkim_error(dkim,
			           "s=%s d=%s: gnutls_pubkey_import() failed",
			           dkim_sig_getselector(sig),
			           dkim_sig_getdomain(sig));

			sig->sig_error = DKIM_SIGERROR_KEYDECODE;

			return DKIM_STAT_OK;
		}

		vstat = gnutls_pubkey_verify_hash(crypto->crypto_pubkey, 0,
		                                  &crypto->crypto_digest,
		                                  &crypto->crypto_sig);
		if (vstat < 0)
			dkim_sig_load_ssl_errors(dkim, sig, rsastat);

		(void) gnutls_pubkey_get_pk_algorithm(crypto->crypto_pubkey,
		                                      &crypto->crypto_keysize);

		sig->sig_keybits = crypto->crypto_keysize;
#else /* USE_GNUTLS */
		if (sig->sig_signalg == DKIM_SIGN_ED25519SHA256)
		{
			char *keydata;
			long keylen;

			keylen = BIO_get_mem_data(key, &keydata);
			crypto->crypto_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
			                                                  NULL,
			                                                  keydata,
			                                                  keylen);
		}
		else
		{
			crypto->crypto_pkey = d2i_PUBKEY_bio(key, NULL);
		}

		if (crypto->crypto_pkey == NULL)
		{
			dkim_sig_load_ssl_errors(dkim, sig, 0);
			dkim_error(dkim,
			           "s=%s d=%s: EVP_PKEY construction failed",
			           dkim_sig_getselector(sig),
			           dkim_sig_getdomain(sig));

			BIO_free(key);

			sig->sig_error = DKIM_SIGERROR_KEYDECODE;

			return DKIM_STAT_OK;
		}

		/* set up the key object */
	    	if (sig->sig_signalg == DKIM_SIGN_ED25519SHA256)
		{
			EVP_MD_CTX *md_ctx;

			if (EVP_PKEY_id(crypto->crypto_pkey) != EVP_PKEY_ED25519)
			{
				dkim_error(dkim,
				           "s=%s d=%s: not an ED25519 key",
				           dkim_sig_getselector(sig),
				           dkim_sig_getdomain(sig));

				BIO_free(key);

				sig->sig_error = DKIM_SIGERROR_KEYDECODE;

				return DKIM_STAT_OK;
			}

			crypto->crypto_in = sig->sig_sig;
			crypto->crypto_inlen = sig->sig_siglen;

			md_ctx = EVP_MD_CTX_new();
			if (md_ctx == NULL)
			{
				dkim_load_ssl_errors(dkim, 0);
				dkim_error(dkim,
				           "failed to initialize digest context");

				BIO_free(key);

				sig->sig_error = DKIM_SIGERROR_KEYDECODE;

				return DKIM_STAT_OK;
			}

			status = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL,
                                                     crypto->crypto_pkey);
			if (status != 1)
			{
				dkim_load_ssl_errors(dkim, 0);
				dkim_error(dkim,
				           "failed to initialize digest context");

				BIO_free(key);
				EVP_MD_CTX_free(md_ctx);

				sig->sig_error = DKIM_SIGERROR_KEYDECODE;

				return DKIM_STAT_OK;
			}

			vstat = EVP_DigestVerify(md_ctx,
			                         crypto->crypto_in,
			                         crypto->crypto_inlen,
			                         digest, diglen);

			EVP_MD_CTX_free(md_ctx);

			crypto->crypto_keysize = EVP_PKEY_size(crypto->crypto_pkey);
		}
		else
		{
			crypto->crypto_key = EVP_PKEY_get1_RSA(crypto->crypto_pkey);
			if (crypto->crypto_key == NULL)
			{
				dkim_sig_load_ssl_errors(dkim, sig, 0);
				dkim_error(dkim,
				           "s=%s d=%s: EVP_PKEY_get1_RSA() failed",
				           dkim_sig_getselector(sig),
				           dkim_sig_getdomain(sig));

				BIO_free(key);

				sig->sig_error = DKIM_SIGERROR_KEYDECODE;

				return DKIM_STAT_OK;
			}

			crypto->crypto_keysize = RSA_size(crypto->crypto_key);
			crypto->crypto_pad = RSA_PKCS1_PADDING;

			crypto->crypto_in = sig->sig_sig;
			crypto->crypto_inlen = sig->sig_siglen;

			sig->sig_keybits = 8 * crypto->crypto_keysize;

			nid = NID_sha1;

			if (dkim_libfeature(dkim->dkim_libhandle,
			                    DKIM_FEATURE_SHA256) &&
			    sig->sig_hashtype == DKIM_HASHTYPE_SHA256)
				nid = NID_sha256;

			vstat = RSA_verify(nid, digest, diglen,
			                   crypto->crypto_in,
			                   crypto->crypto_inlen,
			                   crypto->crypto_key);
		}

		dkim_sig_load_ssl_errors(dkim, sig, 0);

		BIO_free(key);
		EVP_PKEY_free(crypto->crypto_pkey);
		crypto->crypto_pkey = NULL;
		if (crypto->crypto_key != NULL)
		{
			RSA_free(crypto->crypto_key);
			crypto->crypto_key = NULL;
		}
#endif /* USE_GNUTLS */

		if (vstat == 1)
			sig->sig_flags |= DKIM_SIGFLAG_PASSED;
		else
			sig->sig_error = DKIM_SIGERROR_BADSIG;

		sig->sig_flags |= DKIM_SIGFLAG_PROCESSED;
	}

	/* do the body hash check if possible */
	if (dkim->dkim_bodydone && sig->sig_bh == DKIM_SIGBH_UNTESTED &&
	    (sig->sig_flags & DKIM_SIGFLAG_PASSED) != 0)
	{
		u_char *bhash;
		u_char b64buf[BUFRSZ];

		memset(b64buf, '\0', sizeof b64buf);

		dkim_canon_getfinal(sig->sig_bodycanon, &digest, &diglen);

		bhash = dkim_param_get(sig->sig_taglist, (u_char *) "bh");

		dkim_base64_encode(digest, diglen, b64buf, sizeof b64buf);

		if (strcmp((char *) bhash, (char *) b64buf) == 0)
		{
			sig->sig_bh = DKIM_SIGBH_MATCH;
		}
		else
		{
			sig->sig_error = DKIM_SIGERROR_BADSIG;
			sig->sig_bh = DKIM_SIGBH_MISMATCH;
		}
	}

	/*
	**  Fail if t=s was present in the key and the i= and d= domains
	**  don't match.
	*/

	if ((sig->sig_flags & DKIM_SIGFLAG_NOSUBDOMAIN) != 0)
	{
		char *d;
		char *i;

		d = (char *) dkim_param_get(sig->sig_taglist, (u_char *) "d");
		i = (char *) dkim_param_get(sig->sig_taglist, (u_char *) "i");

		if (i != NULL && d != NULL)
		{
			char *at;

			at = strchr(i, '@');
			if (at == NULL)
				at = i;
			else
				at++;

			if (strcasecmp(at, d) != 0)
				sig->sig_error = DKIM_SIGERROR_SUBDOMAIN;
		}
	}

	/*
	**  Fail if the "must be signed" list was set and this signature didn't
	**  cover a must-be-signed header which was present.
	*/

	if (dkim->dkim_libhandle->dkiml_mbs != NULL)
	{
		int c;

		for (c = 0; dkim->dkim_libhandle->dkiml_mbs[c] != NULL; c++)
		{
			if (dkim_get_header(dkim,
			                    dkim->dkim_libhandle->dkiml_mbs[c],
			                    0, 0) != NULL &&
			    !dkim_sig_hdrsigned(sig,
			                        dkim->dkim_libhandle->dkiml_mbs[c]))
			{
				sig->sig_error = DKIM_SIGERROR_MBSFAILED;
				break;
			}
		}
	}

#ifdef _FFR_CONDITIONAL
	/* so far so good... */
	if (sig->sig_error == DKIM_SIGERROR_UNKNOWN &&
	    sig->sig_bh != DKIM_SIGBH_UNTESTED)
	{
		/* recurse if this was a conditional signature */
		if (sig->sig_bh == DKIM_SIGBH_MATCH)
		{
			char *cd;

			cd = (char *) dkim_param_get(sig->sig_taglist,
			                             (u_char *) "!cd");
			if (cd != NULL)
			{
				_Bool found;
				int c;
				DKIM_SIGINFO *csig;

				/* find every match */ 
				found = FALSE;

				for (c = 0; c < dkim->dkim_sigcount; c++)
				{
					csig = dkim->dkim_siglist[c];

					if (strcasecmp(dkim_sig_getdomain(csig),
					               cd) != 0)
						continue;

					if ((csig->sig_flags & DKIM_SIGFLAG_PROCESSED) == 0 ||
					     csig->sig_bh == DKIM_SIGBH_UNTESTED)
					{
						dkim->dkim_cddepth++;
						status = dkim_sig_process(dkim, csig);
						dkim->dkim_cddepth--;
						if (status != DKIM_STAT_OK)
							return status;
					}

					if (DKIM_SIG_CHECK(csig))
					{
						found = TRUE;
						break;
					}
				}

				if (!found)
					sig->sig_error = DKIM_SIGERROR_CONDITIONAL;
			}
		}

		if (sig->sig_error == DKIM_SIGERROR_UNKNOWN)
			sig->sig_error = DKIM_SIGERROR_OK;
	}
#else /* _FFR_CONDITIONAL */
	if (sig->sig_error == DKIM_SIGERROR_UNKNOWN &&
	    sig->sig_bh != DKIM_SIGBH_UNTESTED)
		sig->sig_error = DKIM_SIGERROR_OK;
#endif /* _FFR_CONDITIONAL */

	return DKIM_STAT_OK;
}

/*
**  DKIM_OHDRS -- extract and decode original headers
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	ptrs -- user-provided array of pointers to header strings (updated)
**  	pcnt -- number of pointers available (updated)
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Notes:
**  	If the returned value of pcnt is greater that what it was originally,
**  	then there were more headers than there were pointers.
*/

DKIM_STAT
dkim_ohdrs(DKIM *dkim, DKIM_SIGINFO *sig, u_char **ptrs, int *pcnt)
{
	int n = 0;
	char *z;
	u_char *ch;
	u_char *p;
	u_char *q;
	char *last;

	assert(dkim != NULL);
	assert(ptrs != NULL);
	assert(pcnt != NULL);

	if (dkim->dkim_mode != DKIM_MODE_VERIFY)
		return DKIM_STAT_INVALID;

	/* pick the one we're going to use */
	if (sig == NULL)
	{
		int c;

		for (c = 0; c < dkim->dkim_sigcount; c++)
		{
			sig = dkim->dkim_siglist[c];
			if ((sig->sig_flags & DKIM_SIGFLAG_PROCESSED) != 0 &&
			    (sig->sig_flags & DKIM_SIGFLAG_IGNORE) == 0)
				break;

			sig = NULL;
		}
	}

	/* none useable; return error */
	if (sig == NULL)
		return DKIM_STAT_INVALID;

	/* find the tag */
	z = (char *) dkim_param_get(sig->sig_taglist, (u_char *) "z");
	if (z == NULL || *z == '\0')
	{
		*pcnt = 0;
		return DKIM_STAT_OK;
	}

	/* get memory for the decode */
	if (dkim->dkim_zdecode == NULL)
	{
		dkim->dkim_zdecode = DKIM_MALLOC(dkim, MAXHEADERS);
		if (dkim->dkim_zdecode == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           strlen(z));
			return DKIM_STAT_NORESOURCE;
		}
	}

	/* copy it */
	strlcpy((char *) dkim->dkim_zdecode, z, strlen(z));

	/* decode */
	for (ch = (u_char *) strtok_r(z, "|", &last);
	     ch != NULL;
	     ch = (u_char *) strtok_r(NULL, "|", &last))
	{
		for (p = ch, q = ch; *p != '\0'; p++)
		{
			if (*p == '=')
			{
				char c;

				if (!isxdigit(*(p + 1)) || !isxdigit(*(p + 2)))
				{
					dkim_error(dkim,
					           "invalid trailing character (0x%02x 0x%02x) in z= tag value",
					           *(p + 1), *(p + 2));

					return DKIM_STAT_INVALID;
				}

				c = 16 * dkim_hexchar(*(p + 1)) + dkim_hexchar(*(p + 2));

				p += 2;

				*q = c;
				q++;
			}
			else
			{
				if (q != p)
					*q = *p;
				q++;
			}
		}

		*q = '\0';

		if (n < *pcnt)
			ptrs[n] = ch;
		n++;
	}

	*pcnt = n;

	return DKIM_STAT_OK;
}

/*
**  DKIM_DIFFHEADERS -- compare original headers with received headers
**
**  Parameters:
**  	dkim -- DKIM handle
**  	canon -- header canonicalization mode in use
**  	maxcost -- maximum "cost" of changes to be reported
**  	ohdrs -- original headers, presumably extracted from a "z" tag
**  	nohdrs -- number of headers at "ohdrs" available
**  	out -- pointer to an array of struct dkim_hdrdiff objects (updated)
** 	nout -- counter of handles returned (updated)
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Side effects:
**  	A series of DKIM_HDRDIFF handles is allocated and must later be
**  	destroyed.
*/

DKIM_STAT
dkim_diffheaders(DKIM *dkim, dkim_canon_t canon, int maxcost,
                 char **ohdrs, int nohdrs,
                 struct dkim_hdrdiff **out, int *nout)
{
#ifdef _FFR_DIFFHEADERS
	int n = 0;
	int a = 0;
	int c;
	int status;
	u_char *p;
	u_char *q;
	u_char *end;
	void *cls;
	struct dkim_header *hdr;
	struct dkim_hdrdiff *diffs = NULL;
	struct dkim_dstring *tmphdr;
	struct dkim_dstring **cohdrs;
	DKIM_LIB *lib;
	regaparams_t params;
	regamatch_t matches;
	regex_t re;
	u_char restr[BUFRSZ + 1];

	assert(dkim != NULL);
	assert(out != NULL);
	assert(nout != NULL);

	if (dkim->dkim_mode != DKIM_MODE_VERIFY)
		return DKIM_STAT_INVALID;
	if (maxcost == 0)
		return DKIM_STAT_INVALID;

	tmphdr = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
	if (tmphdr == NULL)
	{
		dkim_error(dkim, "failed to allocate dynamic string");
		return DKIM_STAT_NORESOURCE;
	}

	lib = dkim->dkim_libhandle;
	cls = dkim->dkim_closure;

	memset(&params, '\0', sizeof params);

	params.cost_ins = COST_INSERT;
	params.cost_del = COST_DELETE;
	params.cost_subst = COST_SUBST;

	params.max_cost = maxcost;
	params.max_ins = DKIM_MAXHEADER;
	params.max_del = DKIM_MAXHEADER;
	params.max_subst = DKIM_MAXHEADER;
	params.max_err = maxcost;

	matches.nmatch = 0;
	matches.pmatch = NULL;

	/* canonicalize all the original header fields */
	cohdrs = DKIM_MALLOC(dkim, sizeof(struct dkim_dstring *) * nohdrs);
	if (cohdrs == NULL)
	{
		dkim_error(dkim, strerror(errno));
		return DKIM_STAT_NORESOURCE;
	}

	for (c = 0; c < nohdrs; c++)
	{
		cohdrs[c] = dkim_dstring_new(dkim, DKIM_MAXHEADER, 0);
		if (cohdrs[c] == NULL)
		{
			for (n = 0; n < c; n++)
				dkim_dstring_free(cohdrs[n]);

			DKIM_FREE(dkim, cohdrs);

			dkim_error(dkim, strerror(errno));

			return DKIM_STAT_NORESOURCE;
		}

		status = dkim_canon_header_string(cohdrs[c], canon,
		                                  ohdrs[c], strlen(ohdrs[c]),
		                                  FALSE);
		if (status != DKIM_STAT_OK)
		{
			for (n = 0; n < c; n++)
				dkim_dstring_free(cohdrs[n]);

			DKIM_FREE(dkim, cohdrs);

			dkim_error(dkim, strerror(errno));

			return status;
		}
	}

	for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		dkim_dstring_blank(tmphdr);

		status = dkim_canon_header_string(tmphdr, canon,
		                                  hdr->hdr_text,
		                                  hdr->hdr_textlen, FALSE);
		if (status != DKIM_STAT_OK)
		{
			dkim_dstring_free(tmphdr);
			for (c = 0; c < nohdrs; c++)
				dkim_dstring_free(cohdrs[c]);
			DKIM_FREE(dkim, cohdrs);
			return status;
		}

		memset(restr, '\0', sizeof restr);

		end = restr + sizeof restr;

		for (p = dkim_dstring_get(tmphdr), q = restr;
		     *p != '\0' && q < end - 3;
		     p++)
		{
			if (q == restr)
				*q++ = '^';

			if (*p == '*' ||
			    *p == '\\' ||
			    *p == '$' ||
			    *p == '+' ||
			    *p == '[' ||
			    *p == ']' ||
			    *p == '(' ||
			    *p == ')' ||
			    *p == '.' ||
			    *p == '|')
				*q++ = '\\';

			*q++ = *p;
		}

		*q = '$';

		status = tre_regcomp(&re, restr, REG_NOSUB);
		if (status != 0)
		{
			char err[BUFRSZ + 1];

			memset(err, '\0', sizeof err);

			(void) tre_regerror(status, &re, err, sizeof err);

			dkim_error(dkim, err);

			if (diffs != NULL)
				dkim_mfree(lib, cls, diffs);

			dkim_dstring_free(tmphdr);
			for (c = 0; c < nohdrs; c++)
				dkim_dstring_free(cohdrs[c]);
			DKIM_FREE(dkim, cohdrs);

			return DKIM_STAT_INTERNAL;
		}

		for (c = 0; c < nohdrs; c++)
		{
			/* not even the same header field */
			if (hdr->hdr_namelen != hdr->hdr_textlen &&
			    strncmp(dkim_dstring_get(cohdrs[c]),
			            dkim_dstring_get(tmphdr),
			            hdr->hdr_namelen + 1) != 0)
				continue;

			/* same, no changes at all */
			if (strcmp(dkim_dstring_get(cohdrs[c]),
			           dkim_dstring_get(tmphdr)) == 0)
				continue;

			/* check for approximate match */
			status = tre_regaexec(&re, dkim_dstring_get(cohdrs[c]),
			                      &matches, params, 0);

			if (status == 0)
			{
				if (n + 1 > a)
				{
					int sz;
					struct dkim_hdrdiff *new;

					if (a == 0)
						a = 16;
					else
						a *= 2;

					sz = a * sizeof(struct dkim_hdrdiff);

					new = (struct dkim_hdrdiff *) dkim_malloc(lib,
					                                          cls,
					                                          sz);

					if (new == NULL)
					{
						dkim_error(dkim,
						           "unable to allocate %d byte(s)",
						           sz);

						if (diffs != NULL)
						{
							dkim_mfree(lib, cls,
							           diffs);
						}

						dkim_dstring_free(tmphdr);
						for (c = 0; c < nohdrs; c++)
							dkim_dstring_free(cohdrs[c]);
						DKIM_FREE(dkim, cohdrs);

						return DKIM_STAT_NORESOURCE;
					}

					dkim_mfree(lib, cls, diffs);

					diffs = new;

					sz = (a - n) & sizeof(struct dkim_hdrdiff);
					memset(&diffs[n], '\0', sz);
				}

				diffs[n].hd_old = ohdrs[c];
				diffs[n].hd_new = hdr->hdr_text;

				n++;
			}
		}

		tre_regfree(&re);
	}

	*out = diffs;
	*nout = n;

	dkim_dstring_free(tmphdr);
	for (c = 0; c < nohdrs; c++)
		dkim_dstring_free(cohdrs[c]);
	DKIM_FREE(dkim, cohdrs);

	return DKIM_STAT_OK;
#else /* _FFR_DIFFHEADERS */
	return DKIM_STAT_NOTIMPLEMENT;
#endif /* _FFR_DIFFHEADERS */
}

/*
**  DKIM_HEADER -- process a header
**
**  Parameters:
**  	dkim -- DKIM handle
**  	hdr -- header text
**  	len -- bytes available at "hdr"
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_header(DKIM *dkim, u_char *hdr, size_t len)
{
	u_char *colon;
	u_char *semicolon;
	u_char *end = NULL;
	size_t c;
	struct dkim_header *h;

	assert(dkim != NULL);
	assert(hdr != NULL);
	assert(len != 0);

#ifdef _FFR_RESIGN
	if (dkim->dkim_hdrbind)
		return DKIM_STAT_INVALID;
#endif /* _FFR_RESIGN */

	if (dkim->dkim_state > DKIM_STATE_HEADER)
		return DKIM_STAT_INVALID;
	dkim->dkim_state = DKIM_STATE_HEADER;

	/* enforce RFC 5322, Section 2.2 */
	colon = NULL;
	for (c = 0; c < len; c++)
	{
		if (colon == NULL)
		{
			/*
			**  Field names are printable ASCII; also tolerate
			**  plain whitespace.
			*/

			if (hdr[c] < 32 || hdr[c] > 126)
				return DKIM_STAT_SYNTAX;

			/* the colon is special */
			if (hdr[c] == ':')
				colon = &hdr[c];
		}
		else
		{
			/* field bodies are printable ASCII, SP, HT, CR, LF */
			if (!(hdr[c] != 9 ||  /* HT */
			      hdr[c] != 10 || /* LF */
			      hdr[c] != 13 || /* CR */
			      (hdr[c] >= 32 && hdr[c] <= 126) /* SP, print */ ))
				return DKIM_STAT_SYNTAX;
		}
	}

	if (colon == NULL)
		return DKIM_STAT_SYNTAX;

	end = colon;

	while (end > hdr && isascii(*(end - 1)) && isspace(*(end - 1)))
		end--;

	/* don't allow a field name containing a semicolon */
	semicolon = memchr(hdr, ';', len);
	if (semicolon != NULL && colon != NULL && semicolon < colon)
		return DKIM_STAT_SYNTAX;

	/* see if this is one we should skip */
	if (dkim->dkim_mode == DKIM_MODE_SIGN &&
	    dkim->dkim_libhandle->dkiml_skipre)
	{
		int status;
		unsigned char name[DKIM_MAXHEADER + 1];

		strlcpy((char *) name, (char *) hdr, sizeof name);
		if (end != NULL)
			name[end - hdr] = '\0';

		status = regexec(&dkim->dkim_libhandle->dkiml_skiphdrre,
		                 (char *) name, 0, NULL, 0);

		if (status == 0)
			return DKIM_STAT_OK;
		else
			assert(status == REG_NOMATCH);
	}

	h = DKIM_MALLOC(dkim, sizeof(struct dkim_header));

	if (h == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           sizeof(struct dkim_header));
		return DKIM_STAT_NORESOURCE;
	}

	if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_FIXCRLF) != 0)
	{
		u_char prev = '\0';
		u_char *p;
		u_char *q;
		struct dkim_dstring *tmphdr;

		tmphdr = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
		if (tmphdr == NULL)
		{
			DKIM_FREE(dkim, h);
			return DKIM_STAT_NORESOURCE;
		}

		q = hdr + len;

		for (p = hdr; p < q && *p != '\0'; p++)
		{
			if (*p == '\n' && prev != '\r')		/* bare LF */
			{
				dkim_dstring_catn(tmphdr, CRLF, 2);
			}
			else if (prev == '\r' && *p != '\n')	/* bare CR */
			{
				dkim_dstring_cat1(tmphdr, '\n');
				dkim_dstring_cat1(tmphdr, *p);
			}
			else					/* other */
			{
				dkim_dstring_cat1(tmphdr, *p);
			}

			prev = *p;
		}

		if (prev == '\r')				/* end CR */
			dkim_dstring_cat1(tmphdr, '\n');

		h->hdr_text = dkim_strdup(dkim, dkim_dstring_get(tmphdr),
		                          dkim_dstring_len(tmphdr));

		dkim_dstring_free(tmphdr);
	}
	else
	{
		h->hdr_text = dkim_strdup(dkim, hdr, len);
	}

	if (h->hdr_text == NULL)
	{
		DKIM_FREE(dkim, h);
		return DKIM_STAT_NORESOURCE;
	}

	h->hdr_namelen = end != NULL ? end - hdr : len;
	h->hdr_textlen = len;
	if (colon == NULL)
		h->hdr_colon = NULL;
	else
		h->hdr_colon = h->hdr_text + (colon - hdr);
	h->hdr_flags = 0;
	h->hdr_next = NULL;

	if (dkim->dkim_hhead == NULL)
	{
		dkim->dkim_hhead = h;
		dkim->dkim_htail = h;
	}
	else
	{
		dkim->dkim_htail->hdr_next = h;
		dkim->dkim_htail = h;
	}

	dkim->dkim_hdrcnt++;

	if (h->hdr_colon != NULL)
	{
		if (h->hdr_namelen == DKIM_SIGNHEADER_LEN &&
		    strncasecmp((char *) hdr, DKIM_SIGNHEADER,
		                DKIM_SIGNHEADER_LEN) == 0)
		{
			DKIM_STAT status;
			size_t plen;

			plen = len - (h->hdr_colon - h->hdr_text) - 1;
			status = dkim_process_set(dkim, DKIM_SETTYPE_SIGNATURE,
			                          h->hdr_colon + 1, plen, h,
			                          FALSE, NULL);

			if (status != DKIM_STAT_OK)
				return status;
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_EOH -- declare end-of-headers
** 
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_eoh(DKIM *dkim)
{
	assert(dkim != NULL);

	if (dkim->dkim_mode == DKIM_MODE_VERIFY)
		return dkim_eoh_verify(dkim);
	else
		return dkim_eoh_sign(dkim);
}

/*
**  DKIM_BODY -- pass a body chunk in for processing
**
**  Parameters:
**  	dkim -- DKIM handle
**  	buf -- body chunk
**  	buflen -- number of bytes at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_body(DKIM *dkim, u_char *buf, size_t buflen)
{
	assert(dkim != NULL);
	assert(buf != NULL);

#ifdef _FFR_RESIGN
	if (dkim->dkim_resign != NULL)
		return DKIM_STAT_INVALID;
#endif /* _FFR_RESIGN */

	if (dkim->dkim_state > DKIM_STATE_BODY ||
	    dkim->dkim_state < DKIM_STATE_EOH1)
		return DKIM_STAT_INVALID;
	dkim->dkim_state = DKIM_STATE_BODY;

	if (dkim->dkim_skipbody)
		return DKIM_STAT_OK;

	return dkim_canon_bodychunk(dkim, buf, buflen);
}

/*
**  DKIM_EOM -- declare end-of-body; conduct verification or signing
**
**  Parameters:
**  	dkim -- DKIM handle
**  	testkey -- TRUE iff the a matching key was found but is marked as a
**  	           test key (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_eom(DKIM *dkim, _Bool *testkey)
{
	assert(dkim != NULL);

	if (dkim->dkim_mode == DKIM_MODE_SIGN)
		return dkim_eom_sign(dkim);
	else
		return dkim_eom_verify(dkim, testkey);
}

/*
**  DKIM_CHUNK -- process a message chunk
**
**  Parameters:
**  	dkim -- DKIM handle
**  	buf -- data to process
**  	buflen -- number of bytes at "buf" to process
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_chunk(DKIM *dkim, u_char *buf, size_t buflen)
{
	_Bool bso;
	DKIM_STAT status;
	unsigned char *p;
	unsigned char *end;

	assert(dkim != NULL);

	bso = ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_BADSIGHANDLES) != 0);

	if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_FIXCRLF) == 0)
		dkim->dkim_chunkcrlf = DKIM_CRLF_CRLF;

	/* verify chunking state */
	if (dkim->dkim_chunkstate >= DKIM_CHUNKSTATE_DONE)
	{
		return DKIM_STAT_INVALID;
	}
	else if (dkim->dkim_chunkstate == DKIM_CHUNKSTATE_INIT)
	{
		if (dkim->dkim_hdrbuf == NULL)
		{
			dkim->dkim_hdrbuf = dkim_dstring_new(dkim, BUFRSZ,
			                                     MAXBUFRSZ);
			if (dkim->dkim_hdrbuf == NULL)
				return DKIM_STAT_NORESOURCE;
		}
		else
		{
			dkim_dstring_blank(dkim->dkim_hdrbuf);
		}

		dkim->dkim_chunkstate = DKIM_CHUNKSTATE_HEADER;
		dkim->dkim_chunksm = 0;
	}

	/* process an "end" call */
	if (buf == NULL || buflen == 0)
	{
		if (dkim->dkim_chunkstate == DKIM_CHUNKSTATE_HEADER)
		{
			if (dkim_dstring_len(dkim->dkim_hdrbuf) > 0)
			{
				status = dkim_header(dkim,
				                     dkim_dstring_get(dkim->dkim_hdrbuf),
				                     dkim_dstring_len(dkim->dkim_hdrbuf));
				if (status != DKIM_STAT_OK &&
				    !(status == DKIM_STAT_SYNTAX && bso))
					return status;
			}

			status = dkim_eoh(dkim);
			if (status != DKIM_STAT_OK)
				return status;
		}

		dkim->dkim_chunkstate = DKIM_CHUNKSTATE_DONE;

		return DKIM_STAT_OK;
	}

	/* if we're in body state, just call dkim_body() */
	if (dkim->dkim_chunkstate == DKIM_CHUNKSTATE_BODY)
		return dkim_body(dkim, buf, buflen);

	assert(dkim->dkim_chunkstate == DKIM_CHUNKSTATE_HEADER);

	end = buf + buflen - 1;

	/* process headers */
	for (p = buf; p <= end; p++)
	{
		switch (dkim->dkim_chunksm)
		{
		  case 0:
			if (*p == '\n' &&
			    dkim->dkim_chunkcrlf != DKIM_CRLF_CRLF)
			{
				dkim->dkim_chunkcrlf = DKIM_CRLF_LF;

				/*
				**  If this is a CRLF up front, change state
				**  and write the rest as part of the body.
				*/

				if (dkim->dkim_hhead == NULL &&
				    dkim_dstring_len(dkim->dkim_hdrbuf) == 2)
				{
					status = dkim_eoh(dkim);
					if (status != DKIM_STAT_OK)
						return status;

					dkim->dkim_chunkstate = DKIM_CHUNKSTATE_BODY;
					if (p < end)
					{
						return dkim_body(dkim, p + 1,
						                 end - p);
					}
					else
					{
						return DKIM_STAT_OK;
					}
				}

				dkim_dstring_catn(dkim->dkim_hdrbuf, CRLF, 2);
				dkim->dkim_chunksm = 2;
			}
			else
			{
				dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
				if (*p == '\r')
					dkim->dkim_chunksm = 1;
			}
			break;

		  case 1:
			dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
			if (*p == '\n')
			{
				if (dkim->dkim_chunkcrlf == DKIM_CRLF_UNKNOWN)
					dkim->dkim_chunkcrlf = DKIM_CRLF_CRLF;

				/*
				**  If this is a CRLF up front, change state
				**  and write the rest as part of the body.
				*/

				if (dkim->dkim_hhead == NULL &&
				    dkim_dstring_len(dkim->dkim_hdrbuf) == 2)
				{
					status = dkim_eoh(dkim);
					if (status != DKIM_STAT_OK)
						return status;

					dkim->dkim_chunkstate = DKIM_CHUNKSTATE_BODY;
					if (p < end)
					{
						return dkim_body(dkim, p + 1,
						                 end - p);
					}
					else
					{
						return DKIM_STAT_OK;
					}
				}

				dkim->dkim_chunksm = 2;
			}
			else if (*p != '\r')
			{
				dkim->dkim_chunksm = 0;
			}
			break;
			
		  case 2:
			if (DKIM_ISLWSP(*p))
			{
				dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
				dkim->dkim_chunksm = 0;
				break;
			}
			else if (*p == '\r' &&
			         dkim->dkim_chunkcrlf == DKIM_CRLF_CRLF)
			{
				dkim->dkim_chunksm = 3;
				break;
			}
			else if (*p != '\n' ||
			         dkim->dkim_chunkcrlf != DKIM_CRLF_LF)
			{
				status = dkim_header(dkim,
				                     dkim_dstring_get(dkim->dkim_hdrbuf),
				                     dkim_dstring_len(dkim->dkim_hdrbuf) - 2);
				if (status != DKIM_STAT_OK &&
				    !(status == DKIM_STAT_SYNTAX && bso))
					return status;

				dkim_dstring_blank(dkim->dkim_hdrbuf);
				dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
				dkim->dkim_chunksm = 0;
				break;
			}
			/* FALLTHROUGH */
				
		  case 3:
			if (*p == '\n')
			{
				if (dkim_dstring_len(dkim->dkim_hdrbuf) > 0)
				{
					status = dkim_header(dkim,
					                     dkim_dstring_get(dkim->dkim_hdrbuf),
					                     dkim_dstring_len(dkim->dkim_hdrbuf) - 2);
					if (status != DKIM_STAT_OK &&
					    !(status == DKIM_STAT_SYNTAX &&
					      bso))
						return status;
				}

				status = dkim_eoh(dkim);
				if (status != DKIM_STAT_OK)
					return status;

				dkim->dkim_chunkstate = DKIM_CHUNKSTATE_BODY;

				if (p < end)
					return dkim_body(dkim, p + 1, end - p);
				else
					return DKIM_STAT_OK;
			}
			else
			{
				status = dkim_header(dkim,
				                     dkim_dstring_get(dkim->dkim_hdrbuf),
				                     dkim_dstring_len(dkim->dkim_hdrbuf) - 2);
				if (status != DKIM_STAT_OK &&
				    !(status == DKIM_STAT_SYNTAX && bso))
					return status;

				dkim_dstring_blank(dkim->dkim_hdrbuf);
				dkim_dstring_cat1(dkim->dkim_hdrbuf, '\r');
				dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
				dkim->dkim_chunksm = 0;
			}
			break;

		  default:
			assert(0);
			/* NOTREACHED */
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_MINBODY -- return number of bytes still expected
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	0 -- all canonicalizations satisfied
**  	ULONG_MAX -- at least one canonicalization wants the whole message
**  	other -- bytes required to satisfy all canonicalizations
*/

u_long
dkim_minbody(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim_canon_minbody(dkim);
}

/*
**  DKIM_KEY_SYNTAX -- process a key record parameter set for valid syntax
**
**  Parameters:
**  	dkim -- DKIM context in which this is performed
**  	str -- string to be scanned
**  	len -- number of bytes available at "str"
**
**  Return value:
**  	A DKIM_STAT constant.
*/

DKIM_STAT
dkim_key_syntax(DKIM *dkim, u_char *str, size_t len)
{
	return dkim_process_set(dkim, DKIM_SETTYPE_KEY, str, len, NULL, TRUE,
	                        NULL);
}

/*
**  DKIM_SIG_SYNTAX -- process a signature parameter set for valid syntax
**
**  Parameters:
**  	dkim -- DKIM context in which this is performed
**  	str -- string to be scanned
**  	len -- number of bytes available at "str"
**
**  Return value:
**  	A DKIM_STAT constant.
*/

DKIM_STAT
dkim_sig_syntax(DKIM *dkim, u_char *str, size_t len)
{
	return dkim_process_set(dkim, DKIM_SETTYPE_SIGNATURE, str, len,
	                        NULL, TRUE, NULL);
}

/*
**  DKIM_GETID -- retrieve "id" pointer from a handle
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	The "id" pointer from inside the handle, stored when it was created.
*/

const char *
dkim_getid(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_id;
}

/*
**  DKIM_GETSIGLIST -- retrieve the list of signatures
**
**  Parameters:
**  	dkim -- DKIM handle
**   	sigs -- pointer to a vector of DKIM_SIGINFO pointers (updated)
**   	nsigs -- pointer to an integer to receive the pointer count (updated)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_getsiglist(DKIM *dkim, DKIM_SIGINFO ***sigs, int *nsigs)
{
	assert(dkim != NULL);
	assert(sigs != NULL);
	assert(nsigs != NULL);

	if (dkim->dkim_state < DKIM_STATE_EOH2)
		return DKIM_STAT_INVALID;

	*sigs = dkim->dkim_siglist;
	*nsigs = dkim->dkim_sigcount;

	return DKIM_STAT_OK;
}

/*
**  DKIM_GETSIGNATURE -- retrieve the "final" signature
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	Pointer to a DKIM_SIGINFO handle which is the one libopendkim will
**  	use to return a "final" result; NULL if none could be determined.
*/

DKIM_SIGINFO *
dkim_getsignature(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_signature;
}

/*
**  DKIM_GETSIGHDR_D -- for signing operations, retrieve the complete signature
**                      header, doing so dynamically
**
**  Parameters:
**  	dkim -- DKIM handle
**  	initial -- initial line width
**  	buf -- pointer to buffer containing the signature (returned)
**  	buflen -- number of bytes at "buf" (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Notes:
**  	Per RFC6376 Section 3.7, the signature header returned here does
**  	not contain a trailing CRLF.
*/

DKIM_STAT
dkim_getsighdr_d(DKIM *dkim, size_t initial, u_char **buf, size_t *buflen)
{
	size_t len;
	char *ctx;
	char *pv;
	DKIM_SIGINFO *sig;
	struct dkim_dstring *tmpbuf;

	assert(dkim != NULL);
	assert(buf != NULL);
	assert(buflen != NULL);

	if (dkim->dkim_state != DKIM_STATE_EOM2 ||
	    dkim->dkim_mode != DKIM_MODE_SIGN)
		return DKIM_STAT_INVALID;

#define	DELIMITER	"\001"

	sig = dkim->dkim_signature;
	if (sig == NULL)
		sig = dkim->dkim_siglist[0];

	if ((sig->sig_flags & DKIM_SIGFLAG_KEYLOADED) == 0)
	{
		dkim_error(dkim, "private key load failure");
		return DKIM_STAT_INVALID;
	}

	tmpbuf = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
	if (tmpbuf == NULL)
	{
		dkim_error(dkim, "failed to allocate dynamic string");
		return DKIM_STAT_NORESOURCE;
	}

	if (dkim->dkim_hdrbuf == NULL)
	{
		dkim->dkim_hdrbuf = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
		if (dkim->dkim_hdrbuf == NULL)
		{
			dkim_dstring_free(tmpbuf);
			dkim_error(dkim, "failed to allocate dynamic string");
			return DKIM_STAT_NORESOURCE;
		}
	}
	else
	{
		dkim_dstring_blank(dkim->dkim_hdrbuf);
	}

	/* compute and extract the signature header */
	len = dkim_gensighdr(dkim, sig, tmpbuf, DELIMITER);
	if (len == 0)
	{
		dkim_dstring_free(tmpbuf);
		return DKIM_STAT_INVALID;
	}

	if (dkim->dkim_b64sig != NULL)
		dkim_dstring_cat(tmpbuf, dkim->dkim_b64sig);

	if (dkim->dkim_margin == 0)
	{
		_Bool first = TRUE;

		for (pv = strtok_r((char *) dkim_dstring_get(tmpbuf),
		                   DELIMITER, &ctx);
		     pv != NULL;
		     pv = strtok_r(NULL, DELIMITER, &ctx))
		{
			if (!first)
				dkim_dstring_cat1(dkim->dkim_hdrbuf, ' ');

			dkim_dstring_cat(dkim->dkim_hdrbuf, (u_char *) pv);

			first = FALSE;
		}
	}
	else
	{
		_Bool first = TRUE;
		_Bool forcewrap;
		int pvlen;
		int whichlen;
		char *p;
		char *q;
		char *end;
		char which[MAXTAGNAME + 1];

		len = initial;
		end = which + MAXTAGNAME;

		for (pv = strtok_r((char *) dkim_dstring_get(tmpbuf),
		                   DELIMITER, &ctx);
		     pv != NULL;
		     pv = strtok_r(NULL, DELIMITER, &ctx))
		{
			for (p = pv, q = which; *p != '=' && q <= end; p++, q++)
			{
				*q = *p;
				*(q + 1) = '\0';
			}

			whichlen = strlen(which);

			/* force wrapping of "b=" ? */

			forcewrap = FALSE;
			if (sig->sig_keytype == DKIM_KEYTYPE_RSA)
			{
				u_int siglen;

				siglen = BASE64SIZE(sig->sig_keybits / 8);
				if (strcmp(which, "b") == 0 &&
				    len + whichlen + siglen + 1 >= dkim->dkim_margin)
					forcewrap = TRUE;
			}

			pvlen = strlen(pv);

			if (len == 0 || first)
			{
				dkim_dstring_catn(dkim->dkim_hdrbuf,
				                  (u_char *) pv,
				                  pvlen);
				len += pvlen;
				first = FALSE;
			}
			else if (forcewrap || len + pvlen > dkim->dkim_margin)
			{
				forcewrap = FALSE;
				dkim_dstring_catn(dkim->dkim_hdrbuf,
				                  (u_char *) "\r\n\t", 3);
				len = 8;

				if (strcmp(which, "h") == 0)
				{			/* break at colons */
					_Bool ifirst = TRUE;
					int tmplen;
					char *tmp;
					char *ctx2;

					for (tmp = strtok_r(pv, ":", &ctx2);
					     tmp != NULL;
					     tmp = strtok_r(NULL, ":", &ctx2))
					{
						tmplen = strlen(tmp);

						if (ifirst)
						{
							dkim_dstring_catn(dkim->dkim_hdrbuf,
							                  (u_char *) tmp,
							                  tmplen);
							len += tmplen;
							ifirst = FALSE;
						}
						else if (len + tmplen + 1 > dkim->dkim_margin)
						{
							dkim_dstring_cat1(dkim->dkim_hdrbuf,
							                  ':');
							len += 1;
							dkim_dstring_catn(dkim->dkim_hdrbuf,
							                  (u_char *) "\r\n\t ",
							                  4);
							len = 9;
							dkim_dstring_catn(dkim->dkim_hdrbuf,
							                  (u_char *) tmp,
							                  tmplen);
							len += tmplen;
						}
						else
						{
							dkim_dstring_cat1(dkim->dkim_hdrbuf,
							                  ':');
							len += 1;
							dkim_dstring_catn(dkim->dkim_hdrbuf,
							                  (u_char *) tmp,
							                  tmplen);
							len += tmplen;
						}
					}

				}
				else if (strcmp(which, "b") == 0 ||
				         strcmp(which, "bh") == 0 ||
				         strcmp(which, "z") == 0)
				{			/* break at margins */
					int offset;
					int n;
					char *x;
					char *y;

					offset = whichlen + 1;

					dkim_dstring_catn(dkim->dkim_hdrbuf,
					                  (u_char *) which,
					                  whichlen);
					dkim_dstring_cat1(dkim->dkim_hdrbuf,
					                  '=');

					len += offset;

					dkim_dstring_cat1(dkim->dkim_hdrbuf,
					                  *(pv + offset));
					len++;

					x = pv + offset + 1;
					y = pv + pvlen;

					while (x < y)
					{
						if (dkim->dkim_margin - len == 0)
						{
							dkim_dstring_catn(dkim->dkim_hdrbuf,
							                  (u_char *) "\r\n\t ",
							                  4);
							len = 9;
						}

						n = MIN(dkim->dkim_margin - len,
						        y - x);
						dkim_dstring_catn(dkim->dkim_hdrbuf,
						                  (u_char *) x,
						                  n);
						x += n;
						len += n;
						
					}
				}
				else
				{			/* break at delimiter */
					dkim_dstring_catn(dkim->dkim_hdrbuf,
					                  (u_char *) pv,
					                  pvlen);
					len += pvlen;
				}
			}
			else
			{
				if (!first)
				{
					dkim_dstring_cat1(dkim->dkim_hdrbuf,
					                  ' ');
					len += 1;
				}

				first = FALSE;
				dkim_dstring_catn(dkim->dkim_hdrbuf,
				                  (u_char *) pv,
				                  pvlen);
				len += pvlen;
			}
		}
	}

	*buf = dkim_dstring_get(dkim->dkim_hdrbuf);
	*buflen = dkim_dstring_len(dkim->dkim_hdrbuf);

	dkim_dstring_free(tmpbuf);

	return DKIM_STAT_OK;
}

/*
**  DKIM_GETSIGHDR -- retrieve signature header into a user-provided buffer
**
**  Parameters:
**  	dkim -- libopendkim handle
**  	buf -- buffer into which to write
**  	buflen -- bytes available at "buf"
**  	initial -- width aleady consumed for the first line
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_getsighdr(DKIM *dkim, u_char *buf, size_t buflen, size_t initial)
{
	u_char *p;
	size_t len;
	DKIM_STAT status;

	assert(dkim != NULL);
	assert(buf != NULL);
	assert(buflen > 0);

	status = dkim_getsighdr_d(dkim, initial, &p, &len);
	if (status != DKIM_STAT_OK)
		return status;

	if (len > buflen)
	{
		dkim_error(dkim, "generated signature header too large");
		return DKIM_STAT_NORESOURCE;
	}

	strlcpy((char *) buf, (char *) p, buflen);

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_HDRSIGNED -- retrieve the header list from a signature
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**  	hdr -- header name to find
**
**  Return value:
**  	TRUE iff "sig" had a header list in it and the header "hdr"
**  	appeared in that list.
*/

_Bool
dkim_sig_hdrsigned(DKIM_SIGINFO *sig, u_char *hdr)
{
	size_t len;
	u_char *c1 = NULL;
	u_char *c2 = NULL;
	u_char *start;
	u_char *p;
	u_char *hdrlist;

	assert(sig != NULL);
	assert(hdr != NULL);

	hdrlist = dkim_param_get(sig->sig_taglist, (u_char *) "h");
	if (hdrlist == NULL)
		return FALSE;

	for (p = hdrlist; ; p++)
	{
		len = -1;

		if (*p == ':')
		{
			c1 = c2;
			c2 = p;

			if (c1 == NULL)
			{
				start = hdrlist;
				len = c2 - start; 
			}
			else
			{
				start = c1 + 1;
				len = c2 - c1 - 1;
			}
		}
		else if (*p == '\0')
		{
			if (c2 != NULL)
			{
				start = c2 + 1;
				len = p - c2 - 1;

				if (strncasecmp((char *) hdr, (char *) start,
				                len) == 0)
					return TRUE;
			}
			else
			{
				if (strcasecmp((char *) hdr,
				               (char *) hdrlist) == 0)
					return TRUE;
			}

			break;
		}

		if (len != -1)
		{
			if (strncasecmp((char *) hdr, (char *) start,
			                len) == 0)
				return TRUE;
		}
	}

	return FALSE;
}

/*
**  DKIM_SIG_GETDNSSEC -- retrieve DNSSEC results for a signature
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**
**  Return value:
**  	A DKIM_DNSSEC_* constant.
*/

int
dkim_sig_getdnssec(DKIM_SIGINFO *sig)
{
	assert(sig != NULL);

	return sig->sig_dnssec_key;
}

/*
**  DKIM_SIG_SETDNSSEC -- set DNSSEC results for a signature
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**      dnssec_status -- A DKIM_DNSSEC_* constant
**
*/

void
dkim_sig_setdnssec(DKIM_SIGINFO *sig, int dnssec_status)
{
	assert(sig != NULL);

	switch (dnssec_status) 
	{
	  case DKIM_DNSSEC_BOGUS:
	  case DKIM_DNSSEC_INSECURE:
	  case DKIM_DNSSEC_SECURE:
		sig->sig_dnssec_key = dnssec_status;
		break;

	  default:
		/* just use the unknown value */
		sig->sig_dnssec_key = DKIM_DNSSEC_UNKNOWN;
		break;
	}
}

/*
**  DKIM_SIG_GETREPORTINFO -- retrieve reporting information for a signature
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	hfd -- descriptor to canonicalized header (or NULL) (returned)
**  	bfd -- descriptor to canonicalized body (or NULL) (returned)
**  	addr -- address buffer (or NULL)
**  	addrlen -- size of addr
**  	opts -- options buffer (or NULL)
**  	optslen -- size of opts
**  	smtp -- SMTP reply text buffer (or NULL)
**  	smtplen -- size of smtp
**  	pct -- requested reporting percentage (or NULL)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getreportinfo(DKIM *dkim, DKIM_SIGINFO *sig,
                       int *hfd, int *bfd,
                       u_char *addr, size_t addrlen,
                       u_char *opts, size_t optslen,
                       u_char *smtp, size_t smtplen,
                       u_int *pct)
{
	DKIM_STAT status;
	u_char *p;
	char *sdomain;
	DKIM_SET *set;
	struct timeval timeout;
	unsigned char buf[BUFRSZ];

	assert(dkim != NULL);
	assert(sig != NULL);

	if (dkim->dkim_state != DKIM_STATE_EOM2 ||
	    dkim->dkim_mode != DKIM_MODE_VERIFY)
		return DKIM_STAT_INVALID;

	sdomain = dkim_sig_getdomain(sig);

	/* report descriptors regardless of reporting parameters */
	if (sig->sig_hdrcanon != NULL)
	{
		switch (sig->sig_hashtype)
		{
#ifdef USE_GNUTLS
		  case DKIM_HASHTYPE_SHA1:
		  case DKIM_HASHTYPE_SHA256:
		  {
			struct dkim_sha *sha;

			sha = (struct dkim_sha *) sig->sig_hdrcanon->canon_hash;
			if (hfd != NULL)
				*hfd = sha->sha_tmpfd;

			if (bfd != NULL)
			{
				sha = (struct dkim_sha *) sig->sig_bodycanon->canon_hash;
				*bfd = sha->sha_tmpfd;
			}

			break;
		  }
#else /* USE_GNUTLS */
		  case DKIM_HASHTYPE_SHA1:
		  {
			struct dkim_sha1 *sha1;

			sha1 = (struct dkim_sha1 *) sig->sig_hdrcanon->canon_hash;
			if (hfd != NULL)
				*hfd = sha1->sha1_tmpfd;

			if (bfd != NULL)
			{
				sha1 = (struct dkim_sha1 *) sig->sig_bodycanon->canon_hash;
				*bfd = sha1->sha1_tmpfd;
			}

			break;
		  }

# ifdef HAVE_SHA256
		  case DKIM_HASHTYPE_SHA256:
		  {
			struct dkim_sha256 *sha256;

			sha256 = (struct dkim_sha256 *) sig->sig_hdrcanon->canon_hash;
			if (hfd != NULL)
				*hfd = sha256->sha256_tmpfd;

			if (bfd != NULL)
			{
				sha256 = (struct dkim_sha256 *) sig->sig_bodycanon->canon_hash;
				*bfd = sha256->sha256_tmpfd;
			}

			break;
		  }
# endif /* HAVE_SHA256 */
#endif /* USE_GNUTLS */

		  default:
			assert(0);
		}
	}

	/* see if the signature had an "r=y" tag */
	set = sig->sig_taglist;
	if (set == NULL)
		return DKIM_STAT_INTERNAL;

	p = dkim_param_get(set, (u_char *) "r");
	if (p == NULL || p[0] != 'y' || p[1] != '\0')
	{
		if (addr != NULL)
			addr[0] = '\0';
		if (opts != NULL)
			opts[0] = '\0';
		if (smtp != NULL)
			smtp[0] = '\0';
		if (pct != NULL)
			*pct = (u_int) -1;

		return DKIM_STAT_OK;
	}

	/* see if we've grabbed this set already */
	for (set = dkim_set_first(dkim, DKIM_SETTYPE_SIGREPORT);
	     set != NULL;
	     set = dkim_set_next(set, DKIM_SETTYPE_SIGREPORT))
	{
		if (set->set_name != NULL &&
		    strcasecmp(set->set_name, sdomain) == 0)
			break;
	}

	/* guess not; go to the DNS to get reporting parameters */
	if (set == NULL)
	{
		timeout.tv_sec = dkim->dkim_timeout;
		timeout.tv_usec = 0;

		memset(buf, '\0', sizeof buf);
		status = dkim_repinfo(dkim, sig, &timeout, buf, sizeof buf);
		if (status != DKIM_STAT_OK)
			return status;
		if (buf[0] == '\0')
			return DKIM_STAT_OK;

		status = dkim_process_set(dkim, DKIM_SETTYPE_SIGREPORT,
		                          buf, strlen(buf), NULL, FALSE,
		                          sdomain);
		if (status != DKIM_STAT_OK)
			return status;

		for (set = dkim_set_first(dkim, DKIM_SETTYPE_SIGREPORT);
		     set != NULL;
		     set = dkim_set_next(set, DKIM_SETTYPE_SIGREPORT))
		{
			if (set->set_name != NULL &&
			    strcasecmp(set->set_name, sdomain) == 0)
				break;
		}

		assert(set != NULL);
	}

	if (addr != NULL)
	{
		p = dkim_param_get(set, (u_char *) "ra");
		if (p != NULL)
		{
			memset(addr, '\0', addrlen);
			(void) dkim_qp_decode(p, addr, addrlen - 1);
			p = (u_char *) strchr((char *) addr, '@');
			if (p != NULL)
				*p = '\0';
		}
	}

	if (opts != NULL)
	{
		p = dkim_param_get(set, (u_char *) "ro");
		if (p != NULL)
			strlcpy((char *) opts, (char *) p, optslen);
	}

	if (smtp != NULL)
	{
		p = dkim_param_get(set, (u_char *) "rs");
		if (p != NULL)
		{
			memset(smtp, '\0', smtplen);
			(void) dkim_qp_decode(p, smtp, smtplen - 1);
		}
	}

	if (pct != NULL)
	{
		p = dkim_param_get(set, (u_char *) "rp");
		if (p != NULL)
		{
			u_int out;
			char *q;

			out = strtoul((char *) p, &q, 10);
			if (*q == '\0')
				*pct = out;
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETIDENTITY -- retrieve identity of the signer
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle (or NULL to choose final one)
**  	val -- destination buffer
**  	vallen -- size of destination buffer
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getidentity(DKIM *dkim, DKIM_SIGINFO *sig, u_char *val, size_t vallen)
{
	int len;
	char *param;
	struct dkim_set *set;

	assert(val != NULL);
	assert(vallen != 0);

	if (sig == NULL)
	{
		if (dkim == NULL)
			return DKIM_STAT_INVALID;

		sig = dkim->dkim_signature;
		if (sig == NULL)
			return DKIM_STAT_INVALID;
	}

	set = sig->sig_taglist;

	param = (char *) dkim_param_get(set, (u_char *) "i");
	if (param == NULL)
	{
		param = (char *) dkim_param_get(set, (u_char *) "d");
		if (param == NULL)
			return DKIM_STAT_INTERNAL;

		len = snprintf((char *) val, vallen, "@%s", param);

		return (len < vallen ? DKIM_STAT_OK : DKIM_STAT_NORESOURCE);
	}
	else
	{
		len = dkim_qp_decode((u_char *) param, (u_char *) val,
		                     vallen - 1);

		if (len == -1)
		{
			return DKIM_STAT_SYNTAX;
		}
		else if (len >= vallen)
		{
			return DKIM_STAT_NORESOURCE;
		}
		else
		{
			val[len] = '\0';
			return DKIM_STAT_OK;
		}
	}
}

/*
**  DKIM_SIG_GETCANONLEN -- return canonicalized and total body lengths
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	msglen -- total body length (returned)
**  	canonlen -- total canonicalized length (returned)
**  	signlen -- maximum signed length (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getcanonlen(DKIM *dkim, DKIM_SIGINFO *sig, ssize_t *msglen,
                     ssize_t *canonlen, ssize_t *signlen)
{
	assert(dkim != NULL);
	assert(sig != NULL);

	if (msglen != NULL)
		*msglen = dkim->dkim_bodylen;

	if (canonlen != NULL)
	{
		if (sig->sig_bodycanon == NULL)
			return DKIM_STAT_INTERNAL;
		*canonlen = sig->sig_bodycanon->canon_wrote;
	}

	if (signlen != NULL)
	{
		if (sig->sig_bodycanon == NULL)
			return DKIM_STAT_INTERNAL;
		*signlen = sig->sig_bodycanon->canon_length;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETFLAGS -- retreive signature handle flags
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**
**  Return value:
**  	An unsigned integer which is a bitwise-OR of the DKIM_SIGFLAG_*
**  	constants currently set in the provided handle.
*/

unsigned int
dkim_sig_getflags(DKIM_SIGINFO *sig)
{
	assert(sig != NULL);

	return sig->sig_flags;
}

/*
**  DKIM_SIG_GETBH -- retreive signature handle "bh" test state
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**
**  Return value:
**  	An integer that is one of the DKIM_SIGBH_* constants
**  	indicating the current state of "bh" evaluation of the signature.
*/

int
dkim_sig_getbh(DKIM_SIGINFO *sig)
{
	assert(sig != NULL);

	return sig->sig_bh;
}

/*
**  DKIM_SIG_GETKEYSIZE -- retrieve key size (in bits) when verifying
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**  	bits -- number of bits in the key (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getkeysize(DKIM_SIGINFO *sig, unsigned int *bits)
{
	assert(sig != NULL);
	assert(bits != NULL);

	if (sig->sig_keybits == 0 &&
            sig->sig_signalg != DKIM_SIGN_ED25519SHA256)
		return DKIM_STAT_INVALID;

	*bits = sig->sig_keybits;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETSIGNALG -- retrieve signature algorithm when verifying
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**  	alg -- signature algorithm used (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getsignalg(DKIM_SIGINFO *sig, dkim_alg_t *alg)
{
	assert(sig != NULL);
	assert(alg != NULL);

	*alg = sig->sig_signalg;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETSIGNTIME -- retrieve signature timestamp
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**  	when -- signature timestamp (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getsigntime(DKIM_SIGINFO *sig, uint64_t *when)
{
	assert(sig != NULL);
	assert(when != NULL);

	if (sig->sig_timestamp == 0)
		return DKIM_STAT_INVALID;

	*when = sig->sig_timestamp;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETCANONS -- retrieve canonicalizations used when signing
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle from which to retrieve canonicalizations
**  	hdr -- Pointer to a dkim_canon_t where the header canonicalization
**             should be stored
**  	body -- Pointer to a dkim_canon_t where the body canonicalization
**              should be stored
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getcanons(DKIM_SIGINFO *sig, dkim_canon_t *hdr, dkim_canon_t *body)
{
	assert(sig != NULL);

	if (hdr != NULL)
		*hdr = sig->sig_hdrcanonalg;
	if (body != NULL)
		*body = sig->sig_bodycanonalg;

	return DKIM_STAT_OK;
}

/*
**  DKIM_GET_SIGNER -- get DKIM signature's signer
**
**  Parameters:
**  	dkim -- DKIM signing handle
**
**  Parameters:
**  	Pointer to a buffer containing the signer previously requested,
**  	or NULL if none.
*/

const unsigned char *
dkim_get_signer(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_signer;
}

/*
**  DKIM_SET_SIGNER -- set DKIM signature's signer
**
**  Parameters:
**  	dkim -- DKIM signing handle
**  	signer -- signer to store
**
**  Parameters:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_set_signer(DKIM *dkim, const unsigned char *signer)
{
	assert(dkim != NULL);
	assert(signer != NULL);

	if (dkim->dkim_mode != DKIM_MODE_SIGN)
		return DKIM_STAT_INVALID;

	if (dkim->dkim_signer == NULL)
	{
		dkim->dkim_signer = DKIM_MALLOC(dkim, MAXADDRESS + 1);
		if (dkim->dkim_signer == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           MAXADDRESS + 1);
			return DKIM_STAT_NORESOURCE;
		}
	}

	strlcpy((char *) dkim->dkim_signer, (char *) signer, MAXADDRESS + 1);

	return DKIM_STAT_OK;
}

/*
**  DKIM_GETERROR -- return any stored error string from within the DKIM
**                   context handle
**
**  Parameters:
**  	dkim -- DKIM handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

const char *
dkim_geterror(DKIM *dkim)
{
	assert(dkim != NULL);

	return (const char *) dkim->dkim_error;
}

/*
**  DKIM_GETPARTIAL -- return if the DKIM handle is to be signed using
**                     the bodylength tag (l=)
**
**  Parameters:
**      dkim -- DKIM handle
**
**  Return value:
**      True iff the signature is to include a body length tag
*/

_Bool
dkim_getpartial(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_partial;
}

/*
**  DKIM_SETPARTIAL -- set the DKIM handle to sign using the DKIM body length
**                     tag (l=)
**
**  Parameters:
**      dkim -- DKIM handle
**      value -- new Boolean value
**
**  Return value:
**      DKIM_STAT_INVALID -- "dkim" referenced a verification handle
**      DKIM_STAT_OK -- otherwise
*/

DKIM_STAT
dkim_setpartial(DKIM *dkim, _Bool value)
{
	assert(dkim != NULL);

	if (dkim->dkim_mode != DKIM_MODE_SIGN)
		return DKIM_STAT_INVALID;

	dkim->dkim_partial = value;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SET_MARGIN -- set the margin to use when generating signatures
**
**  Parameters:
**      dkim -- DKIM handle
**      value -- new margin value
**
**  Return value:
**      DKIM_STAT_INVALID -- "dkim" referenced a verification handle,
**  	                     "value" was negative, or this is being called
**  	                     after dkim_eom() completed
**      DKIM_STAT_OK -- otherwise
*/

DKIM_STAT
dkim_set_margin(DKIM *dkim, int value)
{
	assert(dkim != NULL);

	if (dkim->dkim_mode != DKIM_MODE_SIGN || value < 0 ||
	    dkim->dkim_state >= DKIM_STATE_EOM2)
		return DKIM_STAT_INVALID;

	dkim->dkim_margin = (size_t) value;

	return DKIM_STAT_OK;
}

/*
**  DKIM_GETRESULTSTR -- translate a DKIM_STAT_* constant to a string
**
**  Parameters:
**  	result -- DKIM_STAT_* constant to translate
**
**  Return value:
**  	Pointer to a text describing "result", or NULL if none exists
*/

const char *
dkim_getresultstr(DKIM_STAT result)
{
	return dkim_code_to_name(results, result);
}

/*
**  DKIM_SET_DNS_CALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call; should take an opaque context pointer
**  	interval -- how often to call back
**
**  Return value:
**  	DKIM_STAT_OK -- success
**  	DKIM_STAT_INVALID -- invalid use
**  	DKIM_STAT_NOTIMPLEMENT -- underlying resolver doesn't support callbacks
*/

DKIM_STAT
dkim_set_dns_callback(DKIM_LIB *libopendkim, void (*func)(const void *context),
                      unsigned int interval)
{
	assert(libopendkim != NULL);

	if (func != NULL && interval == 0)
		return DKIM_STAT_INVALID;

	libopendkim->dkiml_dns_callback = func;
	libopendkim->dkiml_callback_int = interval;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SET_USER_CONTEXT -- set user context pointer
**
**  Parameters:
**  	dkim -- DKIM handle
**  	ctx -- opaque context pointer
**
**  Return value:
**  	DKIM_STAT_OK
*/

DKIM_STAT
dkim_set_user_context(DKIM *dkim, void *ctx)
{
	assert(dkim != NULL);

	dkim->dkim_user_context = (const void *) ctx;

	return DKIM_STAT_OK;
}

/*
**  DKIM_GET_USER_CONTEXT -- get user context pointer
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	User context associated with a DKIM handle
*/

void *
dkim_get_user_context(DKIM *dkim)
{
	assert(dkim != NULL);

	return (void *) dkim->dkim_user_context;
}

/*
**  DKIM_GETMODE -- return the mode (signing, verifying, etc.) of a handle
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_MODE_* constant.
*/

int
dkim_getmode(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_mode;
}

/*
**  DKIM_GETDOMAIN -- retrieve policy domain from a DKIM context
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	Pointer to the domain used for policy checking or NULL if no domain
**  	could be determined.
*/

u_char *
dkim_getdomain(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_domain;
}

/*
**  DKIM_GETUSER -- retrieve sending user (local-part) from a DKIM context
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	Pointer to the apparent sending user (local-part) or NULL if not known.
*/

u_char *
dkim_getuser(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_user;
}

/*
**  DKIM_SET_KEY_LOOKUP -- set the key lookup function
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call
**
**  Return value:
**  	DKIM_STAT_OK
*/

DKIM_STAT
dkim_set_key_lookup(DKIM_LIB *libopendkim,
                    DKIM_STAT (*func)(DKIM *dkim, DKIM_SIGINFO *sig,
                                      u_char *buf, size_t buflen))
{
	assert(libopendkim != NULL);

	libopendkim->dkiml_key_lookup = func;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SET_SIGNATURE_HANDLE -- set the user handle allocation function
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call
**
**  Return value:
**  	DKIM_STAT_OK -- success
*/

DKIM_STAT
dkim_set_signature_handle(DKIM_LIB *libopendkim, void * (*func)(void *closure))
{
	assert(libopendkim != NULL);

	libopendkim->dkiml_sig_handle = func;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SET_SIGNATURE_HANDLE_FREE -- set the user handle deallocation function
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call
**
**  Return value:
**  	DKIM_STAT_OK
*/

DKIM_STAT
dkim_set_signature_handle_free(DKIM_LIB *libopendkim,
                               void (*func)(void *closure, void *user))
{
	assert(libopendkim != NULL);

	libopendkim->dkiml_sig_handle_free = func;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SET_SIGNATURE_TAGVALUES -- set the user handle population function
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call
**
**  Return value:
**  	DKIM_STAT_OK
*/

DKIM_STAT
dkim_set_signature_tagvalues(DKIM_LIB *libopendkim, void (*func)(void *user,
                                                                 dkim_param_t pcode,
                                                                 const u_char *param,
                                                                 const u_char *value))
{
	assert(libopendkim != NULL);

	libopendkim->dkiml_sig_tagvalues = func;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SET_PRESCREEN -- set the user prescreen function
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call
**
**  Return value:
**  	DKIM_STAT_OK
*/

DKIM_STAT
dkim_set_prescreen(DKIM_LIB *libopendkim, DKIM_CBSTAT (*func)(DKIM *dkim,
                                                              DKIM_SIGINFO **sigs,
                                                              int nsigs))
{
	assert(libopendkim != NULL);

	libopendkim->dkiml_prescreen = func;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SET_FINAL -- set the user final scan function
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call
**
**  Return value:
**  	DKIM_STAT_OK
*/

DKIM_STAT
dkim_set_final(DKIM_LIB *libopendkim, DKIM_CBSTAT (*func)(DKIM *dkim,
                                                          DKIM_SIGINFO **sigs,
                                                          int nsigs))
{
	assert(libopendkim != NULL);

	libopendkim->dkiml_final = func;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETCONTEXT -- retrieve user-provided context from a DKIM_SIGINFO
**
**  Parameters:
**  	siginfo -- pointer to a DKIM_SIGINFO from which to extract context
**
**  Return value:
**  	Pointer to the user context provided by an earlier call to the
**  	handle allocator (see above), or NULL if none was ever set.
*/

void *
dkim_sig_getcontext(DKIM_SIGINFO *siginfo)
{
	assert(siginfo != NULL);

	return siginfo->sig_context;
}

/*
**  DKIM_SIG_GETSELECTOR -- retrieve selector from a DKIM_SIGINFO
**
**  Parameters:
**  	siginfo -- pointer to a DKIM_SIGINFO from which to extract the selector
**
**  Return value:
**  	Pointer to the selector associated with the DKIM_SIGINFO.
*/

unsigned char *
dkim_sig_getselector(DKIM_SIGINFO *siginfo)
{
	assert(siginfo != NULL);

	return siginfo->sig_selector;
}

/*
**  DKIM_SIG_GETDOMAIN -- retrieve domain from a DKIM_SIGINFO
**
**  Parameters:
**  	siginfo -- pointer to a DKIM_SIGINFO from which to extract the domain
**
**  Return value:
**  	Pointer to the domain associated with the DKIM_SIGINFO.
*/

unsigned char *
dkim_sig_getdomain(DKIM_SIGINFO *siginfo)
{
	assert(siginfo != NULL);

	return siginfo->sig_domain;
}

/*
**  DKIM_SIG_SETERROR -- set an error code in a DKIM_SIGINFO
**
**  Parameters:
**  	siginfo -- pointer to a DKIM_SIGINFO from which to extract context
**  	err -- error code to store
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_seterror(DKIM_SIGINFO *siginfo, int err)
{
	assert(siginfo != NULL);

	if (siginfo->sig_error != DKIM_SIGERROR_UNKNOWN)
		return DKIM_STAT_INVALID;

	siginfo->sig_error = err;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETERROR -- retrieve an error code from a DKIM_SIGINFO
**
**  Parameters:
**  	siginfo -- pointer to a DKIM_SIGINFO from which to extract context
**
**  Return value:
**  	A DKIM_SIGERROR_* constant.
*/

int
dkim_sig_geterror(DKIM_SIGINFO *siginfo)
{
	assert(siginfo != NULL);

	return siginfo->sig_error;
}

/*
**  DKIM_SIG_GETERRORSTR -- translate a DKIM_SIGERROR_* constant to a string
**
**  Parameters:
**  	sigerr -- DKIM_SIGERROR_* constant to translate
**
**  Return value:
**  	A pointer to a human-readable expression of "sigerr", or NULL if none
**  	exists.
*/

const char *
dkim_sig_geterrorstr(DKIM_SIGERROR sigerr)
{
	return dkim_code_to_name(sigerrors, sigerr);
}

/*
**  DKIM_SIG_IGNORE -- mark a signature referenced by a DKIM_SIGINFO with
**                     an "ignore" flag
**
**  Parameters:
**  	siginfo -- pointer to a DKIM_SIGINFO to update
**
**  Return value:
**  	None.
*/

void
dkim_sig_ignore(DKIM_SIGINFO *siginfo)
{
	assert(siginfo != NULL);

	siginfo->sig_flags |= DKIM_SIGFLAG_IGNORE;
}

/*
**  DKIM_SSL_VERSION -- return version of OpenSSL that was used to build
**                      the library
**
**  Parameters:
**  	None.
**
**  Return value:
**  	The constant OPENSSL_VERSION_NUMBER as defined by OpenSSL.
*/

unsigned long
dkim_ssl_version(void)
{
#ifdef USE_GNUTLS
	return (GNUTLS_VERSION_NUMBER << 8);
#else /* USE_GNUTLS */
	return OPENSSL_VERSION_NUMBER;
#endif /* USE_GNUTLS */
}

/*
**  DKIM_FLUSH_CACHE -- purge expired records from the cache
**
**  Parameters:
**  	lib -- DKIM library handle, returned by dkim_init()
**
**  Return value:
**  	-1 -- caching is not in effect
**  	>= 0 -- number of purged records
*/

int
dkim_flush_cache(DKIM_LIB *lib)
{
#ifdef QUERY_CACHE
	int err;
#endif /* QUERY_CACHE */

	assert(lib != NULL);

#ifdef QUERY_CACHE
	if (lib->dkiml_cache == NULL)
		return -1;

	return dkim_cache_expire(lib->dkiml_cache, 0, &err);
#else /* QUERY_CACHE */
	return -1;
#endif /* QUERY_CACHE */
}

/*
**  DKIM_GETCACHESTATS -- retrieve cache statistics
**
**  Parameters:
**  	lib -- DKIM library handle, returned by dkim_init()
**  	queries -- number of queries handled (returned)
**  	hits -- number of cache hits (returned)
**  	expired -- number of expired hits (returned)
**  	keys -- number of keys in the cache (returned)
**  	reset -- if TRUE, resets the queries, hits, and expired counters
**
**  Return value:
**  	DKIM_STAT_OK -- request completed
**  	DKIM_STAT_INVALID -- cache not initialized
**  	DKIM_STAT_NOTIMPLEMENT -- function not implemented
**
**  Notes:
**  	Any of the parameters may be NULL if the corresponding datum
**  	is not of interest.
*/

DKIM_STAT
dkim_getcachestats(DKIM_LIB *lib, u_int *queries, u_int *hits, u_int *expired,
                   u_int *keys, _Bool reset)
{
#ifdef QUERY_CACHE
	assert(lib != NULL);

	if (lib->dkiml_cache == NULL)
		return DKIM_STAT_INVALID;

	dkim_cache_stats(lib->dkiml_cache, queries, hits, expired, keys, reset);

	return DKIM_STAT_OK;
#else /* QUERY_CACHE */
	return DKIM_STAT_NOTIMPLEMENT;
#endif /* QUERY_CACHE */
}

/*
**  DKIM_CONDITIONAL -- set conditional domain on a signature
**
**  Parameters:
**  	dkim -- signing handle
**  	domain -- domain name upon which this signature shall depend
**
**  Return value:
**  	DKIM_STAT_OK -- request completed
**  	DKIM_STAT_NOTIMPLEMENT -- function not implemented
*/

DKIM_STAT
dkim_conditional(DKIM *dkim, u_char *domain)
{
#ifdef _FFR_CONDITIONAL
	dkim->dkim_conditional = domain;
	return DKIM_STAT_OK;
#else /* _FFR_CONDITIONAL */
	return DKIM_STAT_NOTIMPLEMENT;
#endif /* _FFR_CONDITIONAL */
}

/*
/*
**  DKIM_GET_SIGSUBSTRING -- retrieve a minimal signature substring for
**                           disambiguation
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	buf -- buffer into which to put the substring
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_get_sigsubstring(DKIM *dkim, DKIM_SIGINFO *sig, char *buf, size_t *buflen)
{
	int c;
	int d;
	int x;
	int b1len;
	int b2len;
	int minlen;
	char *b1;
	char *b2;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(buf != NULL);
	assert(buflen != NULL);

	if (dkim->dkim_minsiglen == 0)
	{
		dkim->dkim_minsiglen = MINSIGLEN;

		for (c = 0; c < dkim->dkim_sigcount - 1; c++)
		{
			b1 = (char *) dkim_param_get(dkim->dkim_siglist[c]->sig_taglist,
			                             (u_char *) "b");
			if (b1 == NULL)
				continue;

			b1len = strlen(b1);

			for (d = c + 1; d < dkim->dkim_sigcount; d++)
			{
				b2 = (char *) dkim_param_get(dkim->dkim_siglist[d]->sig_taglist,
				                             (u_char *) "b");
				if (b2 == NULL)
					continue;

				if (strcmp(b1, b2) == 0)
					break;

				if (strncmp(b1, b2, dkim->dkim_minsiglen) != 0)
					continue;

				b2len = strlen(b2);

				minlen = MIN(b1len, b2len);

				for (x = dkim->dkim_minsiglen; x < minlen; x++)
				{
					if (b1[x] != b2[x])
						break;
				}

				dkim->dkim_minsiglen = x + 1;
			}
		}
	}

	b1 = (char *) dkim_param_get(sig->sig_taglist, (u_char *) "b");
	if (b1 == NULL)
		return DKIM_STAT_SYNTAX;

	minlen = MIN(*buflen, dkim->dkim_minsiglen);
	strncpy(buf, b1, minlen);
	if (minlen < *buflen)
		buf[minlen] = '\0';
	*buflen = minlen;

	return DKIM_STAT_OK;
}

/*
**  DKIM_LIBFEATURE -- determine whether or not a particular library feature
**                     is actually available
**
**  Parameters:
**  	lib -- library handle
**  	fc -- feature code to check
**
**  Return value:
**  	TRUE iff the specified feature was compiled in
*/

_Bool
dkim_libfeature(DKIM_LIB *lib, u_int fc)
{
	u_int idx;
	u_int offset;

	idx = fc / (8 * sizeof(int));
	offset = fc % (8 * sizeof(int));

	if (idx > lib->dkiml_flsize)
		return FALSE;
	return ((lib->dkiml_flist[idx] & (1 << offset)) != 0);
}

/*
**  DKIM_LIBVERSION -- return version of libopendkim at runtime
**
**  Parameters:
**  	None.
**
**  Return value:
**  	Library version, i.e. value of the OPENDKIM_LIB_VERSION macro.
*/

uint32_t
dkim_libversion(void)
{
	return OPENDKIM_LIB_VERSION;
}

/*
**  DKIM_SIG_GETTAGVALUE -- retrieve a tag's value from a signature or its key
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**  	keytag -- TRUE iff we want a key's tag
**  	tag -- name of the tag of interest
**
**  Return value:
**  	Pointer to the string containing the value of the requested key,
**  	or NULL if not present.
**
**  Notes:
**  	This was added for use in determining whether or not a key or
**  	signature contained particular data, for gathering general statistics
**  	about DKIM use.  It is not intended to give applications direct access
**  	to unprocessed signature or key data.  The data returned has not
**  	necessarily been vetted in any way.  Caveat emptor.
*/

u_char *
dkim_sig_gettagvalue(DKIM_SIGINFO *sig, _Bool keytag, u_char *tag)
{
	DKIM_SET *set;

	assert(sig != NULL);
	assert(tag != NULL);

	if (keytag)
		set = sig->sig_keytaglist;
	else
		set = sig->sig_taglist;

	if (set == NULL)
		return NULL;
	else
		return dkim_param_get(set, tag);
}

/*
**  DKIM_SIG_GETSIGNEDHDRS -- retrieve the signed header fields covered by
**                            a signature that passed
**
**  Parameters:
**  	dkim -- DKIM instance
**  	sig -- signature
**  	hdrs -- rectangular array of header field strings
**  	hdrlen -- length of each element of "hdrs"
**  	nhdrs -- size of "hdrs" array (updated)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getsignedhdrs(DKIM *dkim, DKIM_SIGINFO *sig,
                       u_char *hdrs, size_t hdrlen, u_int *nhdrs)
{
	int status;
	u_int n;
	u_char *h;
	u_char *p;
	struct dkim_header **sighdrs;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(nhdrs != NULL);

	if ((sig->sig_flags & DKIM_SIGFLAG_PASSED) == 0 ||
	    sig->sig_bh != DKIM_SIGBH_MATCH)
		return DKIM_STAT_INVALID;

	h = dkim_param_get(sig->sig_taglist, "h");
	assert(h != NULL);

	n = 1;
	for (p = h; *p != '\0'; p++)
	{
		if (*p == ':')
			n++;
	}

	if (*nhdrs < n)
	{
		*nhdrs = n;
		return DKIM_STAT_NORESOURCE;
	}

	assert(hdrs != NULL);

	sighdrs = (struct dkim_header **) DKIM_MALLOC(dkim,
	                                              sizeof(struct dkim_header *) * n);
	if (sighdrs == NULL)
	{
		*nhdrs = 0;
		return DKIM_STAT_NORESOURCE;
	}

	status = dkim_canon_selecthdrs(dkim, h, sighdrs, n);
	if (status == -1)
	{
		DKIM_FREE(dkim, sighdrs);
		return DKIM_STAT_INTERNAL;
	}

	*nhdrs = status;

	for (n = 0; n < status; n++)
		strlcpy(&hdrs[n * hdrlen], sighdrs[n]->hdr_text, hdrlen);

	DKIM_FREE(dkim, sighdrs);

	return DKIM_STAT_OK;
}

/*
**  DKIM_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                                query service to be used, returning any
**                                previous handle
**
**  Parameters:
**  	lib -- DKIM library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

void *
dkim_dns_set_query_service(DKIM_LIB *lib, void *h)
{
	void *old;

	old = lib->dkiml_dns_service;

	lib->dkiml_dns_service = h;

	return old;
}

/*
**  DKIM_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             dkim_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

void
dkim_dns_set_query_start(DKIM_LIB *lib, int (*func)(void *, int,
                                                    unsigned char *,
                                                    unsigned char *,
                                                    size_t, void **))
{
	assert(lib != NULL);

	lib->dkiml_dns_start = func;
}

/*
**  DKIM_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel function
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to cancel running queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- query handle to be canceled
*/

void
dkim_dns_set_query_cancel(DKIM_LIB *lib, int (*func)(void *, void *))
{
	assert(lib != NULL);

	lib->dkiml_dns_cancel = func;
}

/*
**  DKIM_DNS_SET_INIT -- stores a pointer to a resolver init function
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to initialize the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void **srv -- DNS service handle (updated)
*/

void
dkim_dns_set_init(DKIM_LIB *lib, int (*func)(void **))
{
	assert(lib != NULL);

	lib->dkiml_dns_init = func;
}

/*
**  DKIM_DNS_SET_CLOSE -- stores a pointer to a resolver shutdown function
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to initialize the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns void
**  		void *srv -- DNS service handle
*/

void
dkim_dns_set_close(DKIM_LIB *lib, void (*func)(void *))
{
	assert(lib != NULL);

	lib->dkiml_dns_close = func;
}

/*
**  DKIM_DNS_SET_NSLIST -- stores a pointer to a NS list update function
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to update NS list
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int
**  		void *dns -- DNS service handle
**  		const char *nslist -- comma-separated list of nameservers
*/

void
dkim_dns_set_nslist(DKIM_LIB *lib, int (*func)(void *, const char *))
{
	assert(lib != NULL);

	lib->dkiml_dns_setns = func;
}

/*
**  DKIM_DNS_SET_CONFIG -- stores a pointer to a resolver configuration
**                         function
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to update resolver configuration
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int
**  		void *dns -- DNS service handle
**  		const char *config -- opaque configuration string
*/

void
dkim_dns_set_config(DKIM_LIB *lib, int (*func)(void *, const char *))
{
	assert(lib != NULL);

	lib->dkiml_dns_config = func;
}

/*
**  DKIM_DNS_SET_TRUSTANCHOR -- stores a pointer to a trust anchor
**                              configuration function
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to update trust anchor configuration
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int
**  		void *dns -- DNS service handle
**  		const char *trustanchor -- opaque trust anchor string
*/

void
dkim_dns_set_trustanchor(DKIM_LIB *lib, int (*func)(void *, const char *))
{
	assert(lib != NULL);

	lib->dkiml_dns_trustanchor = func;
}

/*
**  DKIM_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a DNS reply
**
**  Parameters:
**  	lib -- DKIM library handle
**  	func -- function to use to wait for a reply
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- handle of query that has completed
**  		struct timeval *timeout -- how long to wait
**  		size_t *bytes -- bytes returned
**  		int *error -- error code returned
**  		int *dnssec -- DNSSEC status returned
*/

void
dkim_dns_set_query_waitreply(DKIM_LIB *lib, int (*func)(void *, void *,
                                                        struct timeval *,
                                                        size_t *, int *,
                                                        int *))
{
	assert(lib != NULL);

	lib->dkiml_dns_waitreply = func;
}

/*
**  DKIM_DNS_NSLIST -- requests update to a nameserver list
**
**  Parameters:
**  	lib -- DKIM library handle
**  	nslist -- comma-separated list of nameservers to use
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

int
dkim_dns_nslist(DKIM_LIB *lib, const char *nslist)
{
	int status;

	assert(lib != NULL);
	assert(nslist != NULL);

	if (lib->dkiml_dns_setns != NULL)
	{
		status = lib->dkiml_dns_setns(lib->dkiml_dns_service, nslist);
		if (status != 0)
			return DKIM_DNS_ERROR;
	}

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_DNS_INIT -- force nameserver (re)initialization
**
**  Parameters:
**  	lib -- DKIM library handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

int
dkim_dns_init(DKIM_LIB *lib)
{
	int status;

	assert(lib != NULL);

	if (lib->dkiml_dnsinit_done)
		return DKIM_DNS_INVALID;

	if (lib->dkiml_dns_close != NULL && lib->dkiml_dns_service != NULL)
	{
		lib->dkiml_dns_close(lib->dkiml_dns_service);
		lib->dkiml_dns_service = NULL;
	}

	if (lib->dkiml_dns_init != NULL)
		status = lib->dkiml_dns_init(&lib->dkiml_dns_service);
	else
		status = DKIM_DNS_SUCCESS;

	if (status == DKIM_DNS_SUCCESS)
		lib->dkiml_dnsinit_done = TRUE;

	return status;
}

/*
**  DKIM_DNS_CLOSE -- force nameserver shutdown
**
**  Parameters:
**  	lib -- DKIM library handle
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

int
dkim_dns_close(DKIM_LIB *lib)
{
	assert(lib != NULL);

	if (lib->dkiml_dnsinit_done &&
	    lib->dkiml_dns_close != NULL &&
	    lib->dkiml_dns_service != NULL)
	{
		lib->dkiml_dns_close(lib->dkiml_dns_service);
		lib->dkiml_dns_service = NULL;
	}

	lib->dkiml_dnsinit_done = FALSE;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_DNS_CONFIG -- requests a change to resolver configuration
**
**  Parameters:
**  	lib -- DKIM library handle
**  	config -- opaque configuration string
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

int
dkim_dns_config(DKIM_LIB *lib, const char *config)
{
	int status;

	assert(lib != NULL);
	assert(config != NULL);

	if (lib->dkiml_dns_config != NULL)
	{
		status = lib->dkiml_dns_config(lib->dkiml_dns_service, config);
		if (status != 0)
			return DKIM_DNS_ERROR;
	}

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_DNS_TRUSTANCHOR -- requests a change to resolver trust anchor data
**
**  Parameters:
**  	lib -- DKIM library handle
**  	trust -- opaque trust anchor string
**
**  Return value:
**  	A DKIM_DNS_* constant.
*/

int
dkim_dns_trustanchor(DKIM_LIB *lib, const char *trust)
{
	int status;

	assert(lib != NULL);
	assert(trust != NULL);

	if (lib->dkiml_dns_trustanchor != NULL)
	{
		status = lib->dkiml_dns_trustanchor(lib->dkiml_dns_service,
		                                    trust);
		if (status != 0)
			return DKIM_DNS_ERROR;
	}

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_ADD_QUERYMETHOD -- add a query method
**
**  Parameters:
**  	dkim -- DKIM signing handle to extend
**  	type -- type of query to add
**  	options -- options to include
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_add_querymethod(DKIM *dkim, const char *type, const char *options)
{
	u_char *p;
	struct dkim_qmethod *q;
	struct dkim_qmethod *lastq;
	char tmp[BUFRSZ + 1];

	assert(dkim != NULL);
	assert(type != NULL);

	if (dkim->dkim_mode != DKIM_MODE_SIGN)
		return DKIM_STAT_INVALID;

	/* confirm valid syntax, per RFC6376 */
	for (p = (u_char *) type; *p != '\0'; p++)
	{
		if (!(isascii(*p) && (isalpha(*p) ||
				      (p != (u_char *) type &&
				       (isalnum(*p) ||
					(*(p+1) != '\0' && *p == '-'))))))
			return DKIM_STAT_INVALID;
	}

	/* do dkim-qp-encode step */
	if (options != NULL)
	{
		int len;

		memset(tmp, '\0', sizeof tmp);

		len = dkim_qp_encode((u_char *) options, tmp, sizeof tmp);
		if (len == -1)
		{
			dkim_error(dkim, "can't encode query options",
			           sizeof(struct dkim_qmethod));
			return DKIM_STAT_NORESOURCE;
		}
	}

	/* check for duplicates */
	lastq = NULL;
	for (q = dkim->dkim_querymethods; q != NULL; q = q->qm_next)
	{
		lastq = q;
		if (strcasecmp(q->qm_type, type) == 0 &&
		    ((q->qm_options == NULL && options == NULL) ||
		     (q->qm_options != NULL && options != NULL &&
		      strcasecmp(q->qm_options, tmp) == 0)))
			return DKIM_STAT_INVALID;
	}

	q = (struct dkim_qmethod *) DKIM_MALLOC(dkim,
	                                        sizeof(struct dkim_qmethod));
	if (q == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           sizeof(struct dkim_qmethod));
		return DKIM_STAT_NORESOURCE;
	}

	q->qm_type = dkim_strdup(dkim, type, 0);
	if (q->qm_type == NULL)
	{
		DKIM_FREE(dkim, q);
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           strlen(type) + 1);
		return DKIM_STAT_NORESOURCE;
	}
		
	if (options != NULL)
	{
		q->qm_options = dkim_strdup(dkim, tmp, 0);
		if (q->qm_options == NULL)
		{
			DKIM_FREE(dkim, q->qm_type);
			DKIM_FREE(dkim, q);
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           strlen(options) + 1);
			return DKIM_STAT_NORESOURCE;
		}
	}
	else
	{
		q->qm_options = NULL;
	}

	q->qm_next = NULL;

	if (lastq == NULL)
		dkim->dkim_querymethods = q;
	else
		lastq->qm_next = q;

	return DKIM_STAT_OK;
}

/*
**  DKIM_ADD_XTAG -- add an extension tag/value
**
**  Parameters:
**  	dkim -- DKIM signing handle to extend
**  	tag -- name of tag to add
**  	value -- value to include
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Notes:
**  	A value that contains spaces won't be wrapped nicely by the signature
**  	generation code.  Support for this should be added later.
*/

DKIM_STAT
dkim_add_xtag(DKIM *dkim, const char *tag, const char *value)
{
	u_char last = '\0';
	dkim_param_t pcode;
	u_char *p;
	struct dkim_xtag *x;

	assert(dkim != NULL);
	assert(tag != NULL);
	assert(value != NULL);

	if (dkim->dkim_mode != DKIM_MODE_SIGN)
		return DKIM_STAT_INVALID;

	/* check that it's not in sigparams */
	if (tag[0] == '\0' || value[0] == '\0')
		return DKIM_STAT_INVALID;
	pcode = dkim_name_to_code(sigparams, tag);
	if (pcode != (dkim_param_t) -1)
		return DKIM_STAT_INVALID;

	/* confirm valid syntax, per RFC6376 */
	for (p = (u_char *) tag; *p != '\0'; p++)
	{
		if (!(isascii(*p) && (isalnum(*p) || *p == '_')))
			return DKIM_STAT_INVALID;
	}

	if (value[0] == '\n' ||
	    value[0] == '\r' ||
	    value[0] == '\t' ||
	    value[0] == ' ')
		return DKIM_STAT_INVALID;

	for (p = (u_char *) value; *p != '\0'; p++)
	{
		/* valid characters in general */
		if (!(*p == '\n' ||
		      *p == '\r' ||
		      *p == '\t' ||
		      *p == ' ' ||
		      (*p >= 0x21 && *p <= 0x7e && *p != 0x3b)))
			return DKIM_STAT_INVALID;

		/* CR has to be followed by LF */
		if (last == '\r' && *p != '\n')
			return DKIM_STAT_INVALID;

		/* LF has to be followed by space or tab */
		if (last == '\n' && *p != ' ' && *p != '\t')
			return DKIM_STAT_INVALID;

		last = *p;
	}

	/* can't end with space */
	if (last == '\n' || last == '\r' ||
	    last == '\t' || last == ' ')
		return DKIM_STAT_INVALID;

	/* check for dupicates */
	for (x = dkim->dkim_xtags; x != NULL; x = x->xt_next)
	{
		if (strcmp(x->xt_tag, tag) == 0)
			return DKIM_STAT_INVALID;
	}

	x = (struct dkim_xtag *) DKIM_MALLOC(dkim, sizeof(struct dkim_xtag));
	if (x == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           sizeof(struct dkim_xtag));
		return DKIM_STAT_NORESOURCE;
	}

	x->xt_tag = dkim_strdup(dkim, tag, 0);
	x->xt_value = dkim_strdup(dkim, value, 0);
	x->xt_next = dkim->dkim_xtags;
	dkim->dkim_xtags = x;

	return DKIM_STAT_OK;
}

/*
**  DKIM_QI_GETNAME -- retrieve the DNS name from a DKIM_QUERYINFO object
**
**  Parameters:
**  	query -- DKIM_QUERYINFO handle
**
**  Return value:
**  	A pointer to a NULL-terminated string indicating the name to be
**  	queried, or NULL on error.
*/

const char *
dkim_qi_getname(DKIM_QUERYINFO *query)
{
	assert(query != NULL);

	return query->dq_name;
}

/*
**  DKIM_QI_GETTYPE -- retrieve the DNS RR type from a DKIM_QUERYINFO object
**
**  Parameters:
**  	query -- DKIM_QUERYINFO handle
**
**  Return value:
**  	The DNS RR type to be queried, or -1 on error.
*/

int
dkim_qi_gettype(DKIM_QUERYINFO *query)
{
	assert(query != NULL);

	return query->dq_type;
}

/*
**  DKIM_SIG_GETQUERIES -- retrieve the queries needed to validate a signature
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	qi -- DKIM_QUERYINFO handle array (returned)
**  	nqi -- number of entries in the "qi" array
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getqueries(DKIM *dkim, DKIM_SIGINFO *sig,
                    DKIM_QUERYINFO ***qi, unsigned int *nqi)
{
	DKIM_QUERYINFO **new;
	DKIM_QUERYINFO *newp;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(qi != NULL);
	assert(nqi != NULL);

	new = DKIM_MALLOC(dkim, sizeof(struct dkim_queryinfo *));
	if (new == NULL)
		return DKIM_STAT_NORESOURCE;

	newp = DKIM_MALLOC(dkim, sizeof(struct dkim_queryinfo));
	if (newp == NULL)
	{
		DKIM_FREE(dkim, new);
		return DKIM_STAT_NORESOURCE;
	}

	memset(newp, '\0', sizeof(struct dkim_queryinfo));

	if (sig->sig_selector != NULL && sig->sig_domain != NULL)
	{
		newp->dq_type = T_TXT;
		snprintf((char *) newp->dq_name, sizeof newp->dq_name,
		         "%s.%s.%s",
		         sig->sig_selector, DKIM_DNSKEYNAME, sig->sig_domain);
	}

	new[0] = newp;

	*qi = new;
	*nqi = 1;

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETHASHES -- retrieve hashes
**
**  Parameters:
**  	sig -- signature from which to get completed hashes
**  	hh -- pointer to header hash buffer (returned)
**  	hhlen -- bytes used at hh (returned)
**  	bh -- pointer to body hash buffer (returned)
**  	bhlen -- bytes used at bh (returned)
**
**  Return value:
**  	DKIM_STAT_OK -- successful completion
**  	DKIM_STAT_INVALID -- hashing hasn't been completed
*/

DKIM_STAT
dkim_sig_gethashes(DKIM_SIGINFO *sig, void **hh, size_t *hhlen,
                   void **bh, size_t *bhlen)
{
	return dkim_canon_gethashes(sig, hh, hhlen, bh, bhlen);
}

/*
**  DKIM_SIGNHDRS -- set the list of header fields to sign for a signature,
**                   overriding the library default
**
**  Parameters:
**  	dkim -- DKIM signing handle to be affected
**  	hdrlist -- array of names of header fields that should be signed
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Notes:
**  	"hdrlist" can be NULL if the library's default is to be used.
*/

DKIM_STAT
dkim_signhdrs(DKIM *dkim, const char **hdrlist)
{
	assert(dkim != NULL);

	if (dkim->dkim_hdrre != NULL)
		regfree(dkim->dkim_hdrre);

	if (hdrlist != NULL)
	{
		int status;
		char buf[BUFRSZ + 1];

		if (dkim->dkim_hdrre == NULL)
		{
			dkim->dkim_hdrre = malloc(sizeof(regex_t));

			if (dkim->dkim_hdrre == NULL)
			{
				dkim_error(dkim, "could not allocate %d bytes",
				           sizeof(regex_t));
				return DKIM_STAT_INTERNAL;
			}
		}

		memset(buf, '\0', sizeof buf);

		(void) strlcpy(buf, "^(", sizeof buf);

		if (!dkim_hdrlist((u_char *) buf, sizeof buf,
		                  (u_char **) dkim->dkim_libhandle->dkiml_requiredhdrs,
		                  TRUE))
			return DKIM_STAT_INVALID;
		if (!dkim_hdrlist((u_char *) buf, sizeof buf,
		                  (u_char **) hdrlist, FALSE))
			return DKIM_STAT_INVALID;

		if (strlcat(buf, ")$", sizeof buf) >= sizeof buf)
			return DKIM_STAT_INVALID;

		status = regcomp(dkim->dkim_hdrre, buf,
		                 (REG_EXTENDED|REG_ICASE));

		if (status != 0)
			return DKIM_STAT_INTERNAL;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_SIG_GETSSLBUF -- get the SSL error buffer, if any
**
**  Parameters:
**  	sig -- signature whose buffer should be retrieved
**
**  Return value:
**  	Pointer to the string, if defined, or NULL otherwise.
*/

const char *
dkim_sig_getsslbuf(DKIM_SIGINFO *sig)
{
	assert(sig != NULL);

	if (sig->sig_sslerrbuf != NULL)
		return dkim_dstring_get(sig->sig_sslerrbuf);
	else
		return NULL;
}

/*
**  DKIM_GETSSLBUF -- get the SSL error buffer, if any
**
**  Parameters:
**  	dkim -- DKIM handle from which to get SSL error
**
**  Return value:
**  	Pointer to the string, if defined, or NULL otherwise.
*/

const char *
dkim_getsslbuf(DKIM *dkim)
{
	assert(dkim != NULL);

	if (dkim->dkim_sslerrbuf != NULL)
		return dkim_dstring_get(dkim->dkim_sslerrbuf);
	else
		return NULL;
}
