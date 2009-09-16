/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dkim_c_id[] = "@(#)$Id: dkim.c,v 1.13 2009/09/16 17:36:11 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdbool.h>
#include <netdb.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <resolv.h>
#include <regex.h>

#ifdef __STDC__
# include <stdarg.h>
#else /* __STDC__ */
# include <varargs.h>
#endif /* _STDC_ */

/* libar includes */
#if USE_ARLIB
# include <ar.h>
#endif /* USE_ARLIB */

/* OpenSSL includes */
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

/* libopendkim includes */
#include "dkim.h"
#include "dkim-types.h"
#include "dkim-tables.h"
#include "dkim-keys.h"
#include "dkim-policy.h"
#include "dkim-util.h"
#include "dkim-canon.h"
#ifdef QUERY_CACHE
# include "dkim-cache.h"
#endif /* QUERY_CACHE */
#ifdef _FFR_DKIM_REPUTATION
# include "dkim-rep.h"
#endif /* _FFR_DKIM_REPUTATION */
#ifdef USE_UNBOUND
# include "dkim-ub.h"
#endif /* USE_UNBOUND */
#include "util.h"
#include "base64.h"
#include "dkim-strl.h"

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

#ifdef _FFR_DIFFHEADERS
# define COST_INSERT		1
# define COST_DELETE		1
# define COST_SUBST		2
#endif /* _FFR_DIFFHEADERS */

#define	BUFRSZ			1024
#define	CRLF			"\r\n"
#define	SP			" "

#define	DEFCLOCKDRIFT		300
#define	DEFTIMEOUT		10

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

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

#define BIO_CLOBBER(x)	if ((x) != NULL) \
			{ \
				BIO_free((x)); \
				(x) = NULL; \
			}

#define RSA_CLOBBER(x)	if ((x) != NULL) \
			{ \
				RSA_free((x)); \
				(x) = NULL; \
			}

#define	EVP_CLOBBER(x)	if ((x) != NULL) \
			{ \
				EVP_PKEY_free((x)); \
				(x) = NULL; \
			}

#define	DSTRING_CLOBBER(x) if ((x) != NULL) \
			{ \
				dkim_dstring_free((x)); \
				(x) = NULL; \
			}

/* macros */
#define DKIM_ISLWSP(x)  ((x) == 011 || (x) == 013 || (x) == 014 || (x) == 040)

/* list of headers which may contain the sender */
const u_char *default_senderhdrs[] =
{
	"from",
	NULL
};

/* recommended list of headers to sign, from RFC4871 section 5.5 */
const u_char *should_signhdrs[] =
{
	"from",
	"sender",
	"reply-to",
	"subject",
	"date",
	"message-id",
	"to",
	"cc",
	"mime-version",
	"content-type",
	"content-transfer-encoding",
	"content-id",
	"content-description",
	"resent-date",
	"resent-from",
	"resent-sender",
	"resent-to",
	"resent-cc",
	"resent-message-id",
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

/* recommended list of headers not to sign, from RFC4871 section 5.5 */
const u_char *should_not_signhdrs[] =
{
	"return-path",
	"received",
	"comments",
	"keywords",
	"bcc",
	"resent-bcc",
	"dkim-signature",
	NULL
};

/* required list of headers to sign */
const u_char *required_signhdrs[] =
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
	DKIM_PLIST *plist;
	DKIM_PLIST *pnext;

	assert(set != NULL);

	for (plist = set->set_plist; plist != NULL; plist = pnext)
	{
		pnext = plist->plist_next;

		CLOBBER(plist);
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

	for (plist = set->set_plist; plist != NULL; plist = plist->plist_next)
	{
		if (strcmp(plist->plist_param, param) == 0)
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

	/* see if we have one already */
	for (plist = set->set_plist; plist != NULL; plist = plist->plist_next)
	{
		if (strcasecmp(plist->plist_param, param) == 0)
			break;
	}

	/* nope; make one and connect it */
	if (plist == NULL)
	{
		plist = (DKIM_PLIST *) DKIM_MALLOC(dkim, sizeof(DKIM_PLIST));
		if (plist == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           sizeof(DKIM_PLIST));
			return -1;
		}
		force = TRUE;
		plist->plist_next = set->set_plist;
		set->set_plist = plist;
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
**
**  Return value:
**  	A DKIM_STAT constant.
*/

DKIM_STAT
dkim_process_set(DKIM *dkim, dkim_set_t type, u_char *str, size_t len,
                 void *udata, _Bool syntax)
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
	       type == DKIM_SETTYPE_KEY ||
	       type == DKIM_SETTYPE_POLICY);

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
	strlcpy(hcopy, str, len + 1);

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

	if (!syntax)
	{
		if (dkim->dkim_sethead == NULL)
			dkim->dkim_sethead = set;
		else
			dkim->dkim_settail->set_next = set;

		dkim->dkim_settail = set;
	}

	set->set_next = NULL;
	set->set_plist = NULL;
	set->set_data = hcopy;
	set->set_udata = udata;
	set->set_bad = FALSE;

	for (p = hcopy; *p != '\0'; p++)
	{
		if (!isascii(*p) || (!isprint(*p) && !isspace(*p)))
		{
			dkim_error(dkim,
			           "invalid character (0x%02x) in %s data",
			           *p, settype);
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
			else if (isalnum(*p))
			{
				param = p;
				state = 1;
			}
			else
			{
				dkim_error(dkim, "syntax error in %s data",
				           settype);
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
				dkim_error(dkim, "syntax error in %s data",
				           settype);
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
		status = dkim_add_plist(dkim, set, param, "", TRUE);
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
		dkim_error(dkim, "syntax error in %s data", settype);
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
	  case DKIM_SETTYPE_SIGNATURE:
		/* make sure required stuff is here */
		if (dkim_param_get(set, "s") == NULL ||
		    dkim_param_get(set, "h") == NULL ||
		    dkim_param_get(set, "d") == NULL ||
		    dkim_param_get(set, "b") == NULL ||
		    dkim_param_get(set, "v") == NULL ||
		    dkim_param_get(set, "a") == NULL)
		{
			dkim_error(dkim, "missing parameter(s) in %s data",
			           settype);
			if (syntax)
				dkim_set_free(dkim, set);
			else
				set->set_bad = TRUE;
			return DKIM_STAT_SYNTAX;
		}

		/* test validity of "t" and "x" */
		value = dkim_param_get(set, "t");
		if (value != NULL)
		{
			unsigned long long tmp = 0;
			char *end;

			errno = 0;

			if (value[0] == '-')
			{
				errno = ERANGE;
				tmp = 0;
			}
			else if (value[0] == '\0')
			{
				errno = EINVAL;
				tmp = 0;
			}
			else
			{
				tmp = strtoull(value, &end, 10);
			}

			if (tmp == ULLONG_MAX || errno != 0 || *end != '\0')
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

		value = dkim_param_get(set, "x");
		if (value != NULL)
		{
			unsigned long long tmp = 0;
			char *end;

			errno = 0;

			if (value[0] == '-')
			{
				errno = ERANGE;
				tmp = 0;
			}
			else if (value[0] == '\0')
			{
				errno = EINVAL;
				tmp = 0;
			}
			else
			{
				tmp = strtoull(value, &end, 10);
			}

			if (tmp == ULLONG_MAX || errno != 0 || *end != '\0')
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
		status = dkim_add_plist(dkim, set, "c", "simple/simple",
		                        FALSE);
		if (status == -1)
		{
			set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}

		/* default for "q" */
		status = dkim_add_plist(dkim, set, "q", "dns/txt", FALSE);
		if (status == -1)
		{
			set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}

  		break;

	  case DKIM_SETTYPE_POLICY:
		if (dkim_param_get(set, "dkim") == NULL)
		{
			dkim_error(dkim, "missing parameter(s) in %s data",
			           settype);
			if (syntax)
				dkim_set_free(dkim, set);
			else
				set->set_bad = TRUE;
			return DKIM_STAT_SYNTAX;
		}

		break;

	  case DKIM_SETTYPE_KEY:
		if (syntax)
		{
			dkim_set_free(dkim, set);
			return DKIM_STAT_OK;
		}

		status = dkim_add_plist(dkim, set, "g", "*", FALSE);
		if (status == -1)
		{
			set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}

		status = dkim_add_plist(dkim, set, "k", "rsa", FALSE);
		if (status == -1)
		{
			set->set_bad = TRUE;
			return DKIM_STAT_INTERNAL;
		}

		status = dkim_add_plist(dkim, set, "s", "*", FALSE);
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
**  	namelen -- length of the header name at "namelen" (or 0)
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
		len = strlen(name);
	else
		len = namelen;

	for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (hdr->hdr_namelen == len &&
		    strncasecmp(hdr->hdr_text, name, len) == 0)
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

	val = dkim_param_get(set, "s");

	if (val == NULL)
		return TRUE;

	strlcpy(buf, val, sizeof buf);

	for (p = strtok_r(buf, ":", &last);
	     p != NULL;
	     p = strtok_r(NULL, ":", &last))
	{
		if (strcmp(p, "*") == 0 ||
		    strcasecmp(p, "email") == 0)
			return TRUE;
	}

	return FALSE;
}

/*
**  DKIM_KEY_GRANOK -- return TRUE iff the granularity of the key is
**                     appropriate to the signature being evaluated
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	v -- "v" tag value from the key (may be NULL)
**  	gran -- granularity string from the retrieved key
**  	user -- sending userid
**
**  Return value:
**  	TRUE iff the value of the granularity is a match for the signer.
*/

static _Bool
dkim_key_granok(DKIM *dkim, DKIM_SIGINFO *sig, u_char *v, u_char *gran,
                char *user)
{
	int status;
	DKIM_SET *set;
	char *at;
	char *end;
	u_char *p;
	char *q;
	char restr[MAXADDRESS + 1];
	char cmp[MAXADDRESS + 1];
	regex_t re;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(gran != NULL);
	assert(user != NULL);

	memset(cmp, '\0', sizeof cmp);

	/* handle empty granularity */
	if (gran[0] == '\0')
	{
		if (v == NULL &&
		    (dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_ACCEPTDK))
			return TRUE;
		else
			return FALSE;
	}

	/* if it's just "*", it matches everything */
	if (gran[0] == '*' && gran[1] == '\0')
		return TRUE;

	/* ensure we're evaluating against a signature data set */
	set = sig->sig_taglist;
	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	/* get the value of the "i" parameter */
	p = dkim_param_get(set, "i");

	/* validate the "i" parameter */
	if (p != NULL)
		dkim_qp_decode(p, cmp, sizeof cmp);
	at = strchr(cmp, '@');
	if (at == NULL || at == cmp)
		strlcpy(cmp, user, sizeof cmp);
	else
		*at = '\0';

	/* if it's not wildcarded, enforce an exact match */
	if (strchr(gran, '*') == NULL)
		return (strcmp(gran, user) == 0);

	/* evaluate the wildcard */
	end = restr + sizeof restr;
	memset(restr, '\0', sizeof restr);
	restr[0] = '^';
	for (p = gran, q = restr + 1; *p != '\0' && q < end - 2; p++)
	{
		if (isascii(*p) && ispunct(*p))
		{
			if (*p == '*')
			{
				*q++ = '.';
				*q++ = '*';
			}
			else
			{
				*q++ = '\\';
				*q++ = *p;
			}
		}
		else
		{
			*q++ = *p;
		}
	}

	if (strlcat(restr, "$", sizeof restr) >= sizeof restr)
		return FALSE;

	status = regcomp(&re, restr, 0);
	if (status != 0)
		return FALSE;

	status = regexec(&re, user, 0, NULL, 0);
	(void) regfree(&re);

	return (status == 0 ? TRUE : FALSE);
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
				strlcpy(tmp, x, sizeof tmp);
				tmp[y - x] = '\0';
				hashalg = dkim_name_to_code(hashes, tmp);
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
dkim_key_hashesok(u_char *hashlist)
{
	u_char *x, *y;
	u_char tmp[BUFRSZ + 1];

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
				strlcpy(tmp, x, sizeof tmp);
				tmp[y - x] = '\0';
				if (dkim_name_to_code(hashes, tmp) != -1)
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

#if 0
/*
**  DKIM_SIG_SIGNEROK -- return TRUE iff the signer is specified in a signed
**                       sender header
**
**  Parameters:
**  	dkim -- DKIM handle
**  	set -- signature set to be checked
**  	hdrs -- names of sender headers
**
**  Return value:
**  	TRUE iff the value of the "i" parameter appears in a signed sender
**  	header.
**
**  Note:
**  	This essentially detects third-party signatures.  It's not of use
**  	yet until SSP addresses this question.
*/

static _Bool
dkim_sig_signerok(DKIM *dkim, DKIM_SET *set, u_char **hdrs)
{
	int status;
	int c;
	int clen;
	struct dkim_header *cur;
	u_char *colon;
	char *i;
	char *user;
	char *domain;
	char buf[MAXADDRESS + 1];
	char addr[MAXADDRESS + 1];
	char signer[MAXADDRESS + 1];

	assert(dkim != NULL);
	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	i = dkim_param_get(set, "i");

	assert(i != NULL);

	dkim_qp_decode(i, signer, sizeof signer);

	/* for each header in the "sender header" list */
	for (c = 0; hdrs[c] != NULL; c++)
	{
		/* for each header in the message */
		for (cur = dkim->dkim_hhead; cur != NULL; cur = cur->hdr_next)
		{
			/* skip unsigned headers */
			if ((cur->hdr_flags & DKIM_HDR_SIGNED) == 0)
				continue;

			/* determine header name size */
			colon = strchr(cur->hdr_text, ':');
			if (colon == NULL)
				clen = strlen(cur->hdr_text);
			else
				clen = colon - cur->hdr_text;

			/* if this is a sender header */
			if (strncasecmp(hdrs[c], cur->hdr_text, clen) == 0)
			{
				if (colon == NULL)
					colon = cur->hdr_text;
				else
					colon += 1;

				strlcpy(buf, colon, sizeof buf);

				status = rfc2822_mailbox_split(buf, &user,
				                               &domain);
				if (status != 0 || domain == NULL ||
				    user == NULL || user[0] == '\0' ||
				    domain[0] == '\0')
					continue;

				snprintf(addr, sizeof addr, "%s@%s",
				         user, domain);

				/* see if the sender matches "i" */
				if (dkim_addrcmp(addr, signer) == 0)
					return TRUE;
			}
		}
	}

	return FALSE;
}
#endif /* 0 */

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
	u_char tmp[DKIM_MAXHEADER + 1];

	assert(dkim != NULL);
	assert(hdrlist != NULL);

	strlcpy(tmp, hdrlist, sizeof tmp);

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
	for (d = 0; ; d++)
	{
		if (required_signhdrs[d] == NULL)
			break;

		found = FALSE;

		for (c = 0; c < nh; c++)
		{
			if (strcasecmp(required_signhdrs[d], ptrs[c]) == 0)
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
	char *i;
	char *d;
	char addr[MAXADDRESS + 1];

	assert(dkim != NULL);
	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	i = dkim_param_get(set, "i");
	d = dkim_param_get(set, "d");

	assert(d != NULL);

	memset(addr, '\0', sizeof addr);

	if (i == NULL)
		snprintf(addr, sizeof addr, "@%s", d);
	else
		dkim_qp_decode(i, addr, sizeof addr);

	at = strchr(addr, '@');
	if (at == NULL)
		return FALSE;

	if (strcasecmp(at + 1, d) == 0)
		return TRUE;

	for (dot = strchr(at, '.'); dot != NULL; dot = strchr(dot + 1, '.'))
	{
		if (strcasecmp(dot + 1, d) == 0)
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
dkim_sig_expired(DKIM_SET *set, time_t drift)
{
	unsigned long long expire;
	unsigned long long nowl;
	time_t now;
	u_char *val;

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	val = dkim_param_get(set, "x");
	if (val == NULL)
		return FALSE;

	expire = strtoull(val, NULL, 10);

	(void) time(&now);
	nowl = (unsigned long long) now;

	return (nowl >= expire + (unsigned long long) drift);
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
	unsigned long long signtime;
	unsigned long long expire;
	u_char *val;

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	val = dkim_param_get(set, "t");
	if (val == NULL)
		return TRUE;
	signtime = strtoull(val, NULL, 10);

	val = dkim_param_get(set, "x");
	if (val == NULL)
		return TRUE;
	expire = strtoull(val, NULL, 10);

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
dkim_sig_future(DKIM_SET *set, time_t drift)
{
	unsigned long long signtime;
	unsigned long long nowl;
	unsigned long long driftl;
	time_t now;
	u_char *val;

	assert(set != NULL);
	assert(set->set_type == DKIM_SETTYPE_SIGNATURE);

	val = dkim_param_get(set, "t");
	if (val == NULL)
		return FALSE;

	signtime = strtoull(val, NULL, 10);

	(void) time(&now);
	nowl = (unsigned long long) now;

	driftl = (unsigned long long) drift;

	return (nowl < signtime - driftl);
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

	v = dkim_param_get(set, "v");

	assert(v != NULL);

	/* check for DKIM_VERSION_SIG */
	if (strcmp(v, DKIM_VERSION_SIG) == 0)
		return TRUE;

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
	int c;
	int hashtype = DKIM_HASHTYPE_UNKNOWN;
	int hstatus;
	size_t b64siglen;
	size_t len;
	DKIM_STAT status;
	off_t signlen = (off_t) -1;
	time_t drift;
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
		if (set->set_bad)
		{
			c--;
			continue;
		}

		dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_UNKNOWN;
#ifdef USE_UNBOUND
		dkim->dkim_siglist[c]->sig_dnssec_key = DKIM_DNSSEC_UNKNOWN;
#endif /* USE_UNBOUND */

		/* store the set */
		dkim->dkim_siglist[c]->sig_taglist = set;

		/* override query method? */
		if (lib->dkiml_querymethod != DKIM_QUERY_UNKNOWN)
			dkim->dkim_siglist[c]->sig_query = lib->dkiml_querymethod;

		/* critical stuff: signing domain */
		param = dkim_param_get(set, "d");
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
		param = dkim_param_get(set, "s");
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
		if (!dkim_sig_versionok(dkim, set))
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
		param = dkim_param_get(set, "c");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_C;
			continue;
		}
		else
		{
			char *q;
			char value[BUFRSZ + 1];

			strlcpy(value, param, sizeof value);

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
		param = dkim_param_get(set, "a");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_MISSING_A;
			continue;
		}
		else
		{
			signalg = dkim_name_to_code(algorithms, param);

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
#ifdef DKIM_SIGN_RSASHA256
			  case DKIM_SIGN_RSASHA256:
				hashtype = DKIM_HASHTYPE_SHA256;
				break;
#endif /* DKIM_SIGN_RSASHA256 */

			  default:
				assert(0);
				/* NOTREACHED */
			}

			dkim->dkim_siglist[c]->sig_signalg = signalg;
			dkim->dkim_siglist[c]->sig_hashtype = hashtype;
		}

		/* determine header list */
		param = dkim_param_get(set, "h");
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
		param = dkim_param_get(set, "l");
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
				signlen = (off_t) strtoul(param, &q, 10);
			}

			if (signlen == ULONG_MAX || errno != 0 || *q != '\0')
			{
				dkim->dkim_siglist[c]->sig_error = DKIM_SIGERROR_INVALID_L;
				continue;
			}
		}

		/* query method */
		param = dkim_param_get(set, "q");
		if (param != NULL)
		{
			_Bool bad_qo = FALSE;
			dkim_query_t q = (dkim_query_t) -1;
			u_char *p;
			char *last;
			u_char *opts;
			u_char tmp[BUFRSZ + 1];
			u_char qtype[BUFRSZ + 1];

			strlcpy(qtype, param, sizeof qtype);

			for (p = strtok_r(qtype, ":", &last);
			     p != NULL;
			     p = strtok_r(NULL, ":", &last))
			{
				opts = strchr(p, '/');
				if (opts != NULL)
				{
					strlcpy(tmp, p, sizeof tmp);
					opts = strchr(tmp, '/');
					*opts = '\0';
					opts++;
					p = tmp;
				}

				/* unknown type */
				q = dkim_name_to_code(querytypes, p);
				if (q == (dkim_query_t) -1)
					continue;

				if (q == DKIM_QUERY_DNS)
				{
					/* "txt" option required (also default) */
					if (opts != NULL &&
					    strcmp(opts, "txt") != 0)
					{
						bad_qo = TRUE;
						continue;
					}
				}

				break;
			}

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

			dkim->dkim_siglist[c]->sig_query = q;
		}

		/* override query method? */
		if (lib->dkiml_querymethod != DKIM_QUERY_UNKNOWN)
			dkim->dkim_siglist[c]->sig_query = lib->dkiml_querymethod;

		/* timestamp */
		param = dkim_param_get(set, "t");
		if (param == NULL)
		{
			dkim->dkim_siglist[c]->sig_timestamp = 0;
		}
		else
		{
			dkim->dkim_siglist[c]->sig_timestamp = strtoull(param,
			                                                NULL,
			                                                10);
		}

		/* body hash */
		param = dkim_param_get(set, "bh");
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
		param = dkim_param_get(set, "b");
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

		b64siglen = strlen(param);
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
			dkim_param_t pcode;
			struct dkim_plist *plist;
			void *user;

			user = dkim->dkim_siglist[c]->sig_context;

			for (plist = set->set_plist;
			     plist != NULL;
			     plist = plist->plist_next)
			{
				pcode = dkim_name_to_code(sigparams,
				                          plist->plist_param);

				(void) lib->dkiml_sig_tagvalues(user,
				                                pcode,
				                                plist->plist_param,
				                                plist->plist_value);
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
**  	Number of bytes written to "dstr".
*/

static size_t
dkim_gensighdr(DKIM *dkim, DKIM_SIGINFO *sig, struct dkim_dstring *dstr,
               char *delim)
{
	_Bool firsthdr;
	int n;
	int status;
	size_t hashlen;
	size_t tmplen;
	u_char *hash;
	struct dkim_header *hdr;
	_Bool *always = NULL;
	u_char tmp[DKIM_MAXHEADER + 1];
	char b64hash[DKIM_MAXHEADER + 1];

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(dstr != NULL);
	assert(delim != NULL);

	n = dkim->dkim_hdrcnt * sizeof(_Bool);
	always = DKIM_MALLOC(dkim, n);
	memset(always, '\0', n);

	/*
	**  We need to generate a DKIM-Signature: header template
	**  and include it in the canonicalization.
	*/

	/* basic required stuff */
	tmplen = dkim_dstring_printf(dstr,
	                             "v=%s;%sa=%s;%sc=%s/%s;%sd=%s;%ss=%s;%st=%llu",
	                             DKIM_VERSION_SIG, delim,
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

	if (dkim->dkim_libhandle->dkiml_sigttl != 0)
	{
		unsigned long long expire;

		expire = sig->sig_timestamp + (unsigned long long) dkim->dkim_libhandle->dkiml_sigttl;
		dkim_dstring_printf(dstr, ";%sx=%llu", delim, expire);
	}

	if (dkim->dkim_signer != NULL)
	{
		dkim_dstring_printf(dstr, ";%si=%s", delim,
		                    dkim->dkim_signer);
	}

	memset(b64hash, '\0', sizeof b64hash);

	(void) dkim_canon_closebody(dkim);
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
	for (n = 0; n < dkim->dkim_hdrcnt; n++)
		always[n] = TRUE;

	firsthdr = TRUE;

	for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if ((hdr->hdr_flags & DKIM_HDR_SIGNED) == 0)
			continue;

		memset(tmp, '\0', sizeof tmp);
		strncpy(tmp, hdr->hdr_text,
		        MIN(DKIM_MAXHEADER, hdr->hdr_namelen));

		if (!firsthdr)
		{
			dkim_dstring_cat(dstr, ":");
		}
		else
		{
			dkim_dstring_cat(dstr, ";");
			dkim_dstring_cat(dstr, delim);
			dkim_dstring_cat(dstr, "h=");
		}

		firsthdr = FALSE;

		dkim_dstring_cat(dstr, tmp);

		if (dkim->dkim_libhandle->dkiml_alwayshdrs != NULL)
		{
			u_char **ah = dkim->dkim_libhandle->dkiml_alwayshdrs;

			for (n = 0; ah[n] != NULL && n < dkim->dkim_hdrcnt; n++)
			{
				if (strcasecmp(tmp, ah[n]) == 0)
				{
					always[n] = FALSE;
					break;
				}
			}
		}
	}

	/* apply any "always sign" list */
	if (dkim->dkim_libhandle->dkiml_alwayshdrs != NULL)
	{
		u_char **ah = dkim->dkim_libhandle->dkiml_alwayshdrs;

		for (n = 0; ah[n] != NULL && n < dkim->dkim_hdrcnt; n++)
		{
			if (always[n])
			{
				if (!firsthdr)
				{
					dkim_dstring_cat(dstr, ":");
				}
				else
				{
					dkim_dstring_cat(dstr, ";");
					dkim_dstring_cat(dstr, delim);
					dkim_dstring_cat(dstr, "h=");
				}

				firsthdr = FALSE;

				dkim_dstring_cat(dstr, ah[n]);
			}
		}
	}

	/* if diagnostic headers were requested, include 'em */
	if (dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_ZTAGS)
	{
		_Bool first;
		char *p;
		char *q;
		char *end;
		size_t len;

		first = TRUE;

		end = tmp + sizeof tmp - 1;

		dkim_dstring_cat(dstr, ";");
		dkim_dstring_cat(dstr, delim);
		dkim_dstring_cat(dstr, "z=");

		for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			memset(tmp, '\0', sizeof tmp);
			q = tmp;
			len = sizeof tmp - 1;

			if (!first)
			{
				tmp[0] = '|';
				q++;
				len--;
			}

			first = FALSE;

			for (p = hdr->hdr_text; *p != '\0'; p++)
			{
				if (q >= end)
					break;

				if ((*p >= 0x21 && *p <= 0x3a) ||
				    *p == 0x3c ||
				    (*p >= 0x3e && *p <= 0x7e))
				{
					*q = *p;
					q++;
					len--;
				}
				else
				{
					snprintf(q, len, "=%02X", *p);
					q += 3;
					len -= 3;
				}
			}

			dkim_dstring_cat(dstr, tmp);
		}
	}

	/* and finally, an empty b= */
	dkim_dstring_cat(dstr, ";");
	dkim_dstring_cat(dstr, delim);
	dkim_dstring_cat(dstr, "b=");

	DKIM_FREE(dkim, always);

	return dkim_dstring_len(dstr);
}

/*
**  DKIM_GETSENDER -- determine sender (actually just multi-search)
**
**  Parameters:
**  	dkim -- DKIM handle
**  	hdrs -- list of header names to find
**
**  Return value:
**  	Pointer to the first such header found, or NULL if none.
*/

static struct dkim_header *
dkim_getsender(DKIM *dkim, u_char **hdrs)
{
	int c;
	size_t hlen;
	struct dkim_header *cur;

	assert(dkim != NULL);
	assert(hdrs != NULL);

	for (c = 0; hdrs[c] != NULL; c++)
	{
		hlen = strlen(hdrs[c]);

		for (cur = dkim->dkim_hhead; cur != NULL; cur = cur->hdr_next)
		{
			if (hlen == cur->hdr_namelen &&
			    strncasecmp(hdrs[c], cur->hdr_text, hlen) == 0)
				return cur;
		}
	}

	return NULL;
}

/*
**  DKIM_GET_POLICY -- request and parse a domain's policy record
**
**  Parameters:
**  	dkim -- DKIM handle
**  	query -- string to query
**  	excheck -- existence check rather than TXT query
**  	qstatus -- query status (returned)
**  	policy -- policy found (returned)
**  	pflags -- policy flags (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

static DKIM_STAT
dkim_get_policy(DKIM *dkim, char *query, _Bool excheck, int *qstatus,
                dkim_policy_t *policy, int *pflags)
{
	int status = 0;
	int qstat = NOERROR;
	unsigned int lpflags;
	dkim_policy_t lpolicy;
	DKIM_STAT pstatus;
	unsigned char buf[BUFRSZ + 1];

	assert(dkim != NULL);
	assert(query != NULL);
	assert(qstatus != NULL);
	assert(policy != NULL);
	assert(pflags != NULL);

	if (dkim->dkim_libhandle->dkiml_policy_lookup != NULL)
	{
		DKIM_CBSTAT cbstatus;

		cbstatus = dkim->dkim_libhandle->dkiml_policy_lookup(dkim,
		                                                     query,
		                                                     excheck,
		                                                     buf,
		                                                     sizeof buf,
		                                                     &qstat);

		switch (cbstatus)
		{
		  case DKIM_CBSTAT_CONTINUE:
			status = 1;
			break;

		  case DKIM_CBSTAT_REJECT:
			return DKIM_STAT_CBREJECT;

		  case DKIM_CBSTAT_TRYAGAIN:
			return DKIM_STAT_CBTRYAGAIN;

		  case DKIM_CBSTAT_NOTFOUND:
			break;

		  case DKIM_CBSTAT_ERROR:
			return DKIM_STAT_CBERROR;

		  default:
			return DKIM_STAT_CBINVALID;
		}
	}
	else
	{
		dkim_query_t qtype;
		DKIM_SIGINFO *sig;

		sig = dkim_getsignature(dkim);
		if (sig == NULL)
			qtype = DKIM_QUERY_DEFAULT;
		else
			qtype = sig->sig_query;

		switch (qtype)
		{
		  case DKIM_QUERY_DNS:
			status = dkim_get_policy_dns(dkim, query, excheck,
			                             buf, sizeof buf, &qstat);
			break;

		  case DKIM_QUERY_FILE:
			status = dkim_get_policy_file(dkim, query,
			                              buf, sizeof buf, &qstat);
			break;

		  default:
			assert(0);
			/* just to silence -Wall */
			return -1;
		}
	}

	if (status == -1)
		return DKIM_STAT_CANTVRFY;

	*qstatus = qstat;
	if (!excheck && qstat == NOERROR && status == 1)
	{
		char *p;
		struct dkim_set *set;

		pstatus = dkim_process_set(dkim, DKIM_SETTYPE_POLICY,
		                           buf, strlen(buf), NULL, FALSE);
		if (pstatus != DKIM_STAT_OK)
			return pstatus;

		lpolicy = DKIM_POLICY_DEFAULT;
		lpflags = 0;

		set = dkim_set_first(dkim, DKIM_SETTYPE_POLICY);

		p = dkim_param_get(set, "dkim");
		if (p != NULL)
			lpolicy = dkim_name_to_code(policies, p);

		p = dkim_param_get(set, "t");
		if (p != NULL)
		{
			u_int flag;
			char *t;
			char *last;
			char tmp[BUFRSZ + 1];

			strlcpy(tmp, p, sizeof tmp);

			for (t = strtok_r(tmp, ":", &last);
			     t != NULL;
			     t = strtok_r(NULL, ":", &last))
			{
				flag = (u_int) dkim_name_to_code(policyflags,
				                                 t);
				if (flag != (u_int) -1)
					lpflags |= flag;
			}
		}

		*policy = lpolicy;
		*pflags = lpflags;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_GET_KEY -- acquire a public key used for verification
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_get_key(DKIM *dkim, DKIM_SIGINFO *sig)
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
		if (strcmp(osig->sig_domain, sig->sig_domain) != 0 ||
		    strcmp(osig->sig_selector, sig->sig_selector) != 0)
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
		                          strlen(buf), NULL, FALSE);
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
	p = dkim_param_get(set, "v");
	if (p != NULL && strcmp(p, DKIM_VERSION_KEY) != 0)
	{
		dkim_error(dkim, "invalid key version `%s'", p);
		sig->sig_error = DKIM_SIGERROR_KEYVERSION;
		return DKIM_STAT_SYNTAX;
	}

	/* then make sure the hash type is something we can handle */
	p = dkim_param_get(set, "h");
	if (!dkim_key_hashesok(p))
	{
		dkim_error(dkim, "unknown hash `%s'", p);
		sig->sig_error = DKIM_SIGERROR_KEYUNKNOWNHASH;
		return DKIM_STAT_SYNTAX;
	}
	/* ...and that this key is approved for this signature's hash */
	else if (!dkim_key_hashok(sig, p))
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

	/* check key granularity */
	p = dkim_param_get(set, "g");
	if (p != NULL)
	{
		char *at;
		char *v;

		v = dkim_param_get(set, "v");

		memset(buf, '\0', sizeof buf);
		dkim_sig_getidentity(dkim, sig, buf, sizeof buf);

		at = strchr(buf, '@');
		if (at != NULL)
			*at = '\0';

		if (!dkim_key_granok(dkim, sig, v, p, buf))
		{
			dkim_error(dkim, "granularity mismatch");
			sig->sig_error = DKIM_SIGERROR_GRANULARITY;
			return DKIM_STAT_CANTVRFY;
		}
	}

	/* then key type */
	p = dkim_param_get(set, "k");
	if (p == NULL)
	{
		dkim_error(dkim, "key type missing");
		sig->sig_error = DKIM_SIGERROR_KEYTYPEMISSING;
		return DKIM_STAT_SYNTAX;
	}
	else if (dkim_name_to_code(keytypes, p) == -1)
	{
		dkim_error(dkim, "unknown key type `%s'", p);
		sig->sig_error = DKIM_SIGERROR_KEYTYPEUNKNOWN;
		return DKIM_STAT_SYNTAX;
	}

	if (!gotkey)
	{
		/* decode the key */
		sig->sig_b64key = dkim_param_get(set, "p");
		if (sig->sig_b64key == NULL)
		{
			dkim_error(dkim, "key missing");
			return DKIM_STAT_SYNTAX;
		}
		else if (sig->sig_b64key[0] == '\0')
		{
			return DKIM_STAT_REVOKED;
		}
		sig->sig_b64keylen = strlen(sig->sig_b64key);

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
	p = dkim_param_get(set, "t");
	if (p != NULL)
	{
		u_int flag;
		char *t;
		char *last;
		char tmp[BUFRSZ + 1];

		strlcpy(tmp, p, sizeof tmp);

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
	_Bool found;
	_Bool keep;
	_Bool tmp;
	DKIM_STAT status;
	int c;
	int hashtype = DKIM_HASHTYPE_UNKNOWN;
	size_t len = 0;
	DKIM_CANON *bc;
	DKIM_CANON *hc;
	struct dkim_header *hdr;
	DKIM_LIB *lib;

	assert(dkim != NULL);

	if (dkim->dkim_state >= DKIM_STATE_EOH2)
		return DKIM_STAT_INVALID;
	if (dkim->dkim_state < DKIM_STATE_EOH2)
		dkim->dkim_state = DKIM_STATE_EOH2;

	lib = dkim->dkim_libhandle;
	assert(lib != NULL);

	tmp = ((lib->dkiml_flags & DKIM_LIBFLAGS_TMPFILES) != 0);
	keep = ((lib->dkiml_flags & DKIM_LIBFLAGS_KEEPFILES) != 0);

	dkim->dkim_version = lib->dkiml_version;

	/*
	**  Verify that all the required headers are present and
	**  marked for signing.
	*/

	for (c = 0; required_signhdrs[c] != NULL; c++)
	{
		found = FALSE;
		len = strlen(required_signhdrs[c]);

		for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (hdr->hdr_namelen == len &&
			    strncasecmp(hdr->hdr_text, required_signhdrs[c],
			                len) == 0)
			{
				found = TRUE;
				break;
			}
		}

		if (!found)
		{
			dkim_error(dkim, "required header \"%s\" not found",
			           required_signhdrs[c]);
			dkim->dkim_state = DKIM_STATE_UNUSABLE;
			return DKIM_STAT_SYNTAX;
		}
	}

	/* determine hash type */
	switch (dkim->dkim_signalg)
	{
	  case DKIM_SIGN_RSASHA1:
		hashtype = DKIM_HASHTYPE_SHA1;
		break;

#ifdef DKIM_SIGN_RSASHA256
	  case DKIM_SIGN_RSASHA256:
		hashtype = DKIM_HASHTYPE_SHA256;
		break;
#endif /* DKIM_SIGN_RSASHA256 */

	  default:
		assert(0);
		/* NOTREACHED */
	}

	/* initialize signature and canonicalization for signing */
	dkim->dkim_siglist = DKIM_MALLOC(dkim, sizeof(DKIM_SIGINFO *));
	if (dkim->dkim_siglist == NULL)
	{
		dkim_error(dkim, "failed to allocate %d byte(s)",
		           sizeof(DKIM_SIGINFO *));
		return DKIM_STAT_NORESOURCE;
	}

	dkim->dkim_siglist[0] = DKIM_MALLOC(dkim, sizeof(struct dkim_siginfo));
	if (dkim->dkim_siglist[0] == NULL)
	{
		dkim_error(dkim, "failed to allocate %d byte(s)",
		           sizeof(struct dkim_siginfo));
		return DKIM_STAT_NORESOURCE;
	}
	dkim->dkim_sigcount = 1;
	memset(dkim->dkim_siglist[0], '\0', sizeof(struct dkim_siginfo));
	dkim->dkim_siglist[0]->sig_domain = dkim->dkim_domain;
	dkim->dkim_siglist[0]->sig_selector = dkim->dkim_selector;
	dkim->dkim_siglist[0]->sig_hashtype = hashtype;
	dkim->dkim_siglist[0]->sig_signalg = dkim->dkim_signalg;

	status = dkim_add_canon(dkim, TRUE, dkim->dkim_hdrcanonalg,
	                        hashtype, NULL, NULL, 0, &hc);
	if (status != DKIM_STAT_OK)
		return status;

	status = dkim_add_canon(dkim, FALSE, dkim->dkim_bodycanonalg,
	                        hashtype, NULL, NULL, dkim->dkim_signlen, &bc);
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

		dkim->dkim_siglist[0]->sig_timestamp = (unsigned long long) now;
	}


	/* initialize all canonicalizations */
	status = dkim_canon_init(dkim, tmp, keep);
	if (status != DKIM_STAT_OK)
		return status;

	/* run the headers */
	status = dkim_canon_runheaders(dkim, TRUE);
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
	DKIM_STAT status;
	int c;
	struct dkim_header *sender;
	char *user;
	char *domain;
	DKIM_LIB *lib;
	DKIM_SET *set;

	assert(dkim != NULL);

	if (dkim->dkim_state >= DKIM_STATE_EOH2)
		return DKIM_STAT_INVALID;
	if (dkim->dkim_state < DKIM_STATE_EOH1)
		dkim->dkim_state = DKIM_STATE_EOH1;

	lib = dkim->dkim_libhandle;
	assert(lib != NULL);

	tmp = ((lib->dkiml_flags & DKIM_LIBFLAGS_TMPFILES) != 0);
	keep = ((lib->dkiml_flags & DKIM_LIBFLAGS_KEEPFILES) != 0);

	/* populate some stuff like dkim_sender, dkim_domain, dkim_user */
	sender = dkim_getsender(dkim, dkim->dkim_libhandle->dkiml_senderhdrs);
	if (sender == NULL)
	{
		dkim_error(dkim, "no sender headers detected");
		dkim->dkim_state = DKIM_STATE_UNUSABLE;
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

	status = rfc2822_mailbox_split(dkim->dkim_sender,
	                               (char **) &user,
	                               (char **) &domain);
	if (status != 0 || domain == NULL || user == NULL ||
	    domain[0] == '\0' || user[0] == '\0')
	{
		dkim_error(dkim, "can't determine sender address");
		dkim->dkim_state = DKIM_STATE_UNUSABLE;
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

	/* allocate the siginfo array if not already done */
	if (dkim->dkim_siglist == NULL)
	{
		/* count the signatures */
		for (set = dkim_set_first(dkim, DKIM_SETTYPE_SIGNATURE);
		     set != NULL;
		     set = dkim_set_next(set, DKIM_SETTYPE_SIGNATURE))
		{
			if (!set->set_bad)
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
	if (lib->dkiml_prescreen != NULL)
	{
		status = lib->dkiml_prescreen(dkim,
		                              dkim->dkim_siglist,
		                              dkim->dkim_sigcount);
		switch (status)
		{
		  case DKIM_CBSTAT_CONTINUE:
			break;

		  case DKIM_CBSTAT_REJECT:
			return DKIM_STAT_CBREJECT;

		  case DKIM_CBSTAT_TRYAGAIN:
			return DKIM_STAT_CBTRYAGAIN;

		  default:
			return DKIM_STAT_CBINVALID;
		}
	}

	dkim->dkim_state = DKIM_STATE_EOH2;

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
		return DKIM_STAT_NOSIG;
	}

	/* run the headers */
	status = dkim_canon_runheaders(dkim, FALSE);
	if (status != DKIM_STAT_OK)
		return status;

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
					return status;
			}
		}
	}

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
			return DKIM_STAT_CANTVRFY;
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
	u_int l;
	size_t diglen;
	size_t siglen = 0;
	size_t n;
	size_t len;
	DKIM_STAT ret;
	u_char *digest;
	u_char *signature = NULL;
	BIO *key;
	DKIM_SIGINFO *sig;
	DKIM_CANON *hc;
	struct dkim_header hdr;
	u_char tmp[DKIM_MAXHEADER + 1];

	assert(dkim != NULL);

	if (dkim->dkim_state >= DKIM_STATE_EOM2)
		return DKIM_STAT_INVALID;
	if (dkim->dkim_state < DKIM_STATE_EOM2)
		dkim->dkim_state = DKIM_STATE_EOM2;

	if (dkim->dkim_chunkstate != DKIM_CHUNKSTATE_INIT &&
	    dkim->dkim_chunkstate != DKIM_CHUNKSTATE_DONE)
		return DKIM_STAT_INVALID;

	/* finalize body canonicalizations */
	(void) dkim_canon_closebody(dkim);

	dkim->dkim_bodydone = TRUE;

	/* set signature timestamp */
	if (dkim->dkim_libhandle->dkiml_fixedtime != 0)
		dkim->dkim_timestamp = dkim->dkim_libhandle->dkiml_fixedtime;
	else
		(void) time(&dkim->dkim_timestamp);

	/* sign with l= if requested */
	if ((dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_SIGNLEN) != 0)
		dkim->dkim_partial = TRUE;

	/* get signature and canonicalization handles */
	assert(dkim->dkim_siglist != NULL);
	assert(dkim->dkim_siglist[0] != NULL);
	sig = dkim->dkim_siglist[0];
	hc = sig->sig_hdrcanon;

	/* determine key properties */
	key = BIO_new_mem_buf(dkim->dkim_key, dkim->dkim_keylen);
	if (key == NULL)
	{
		dkim_error(dkim, "BIO_new_mem_buf() failed");
		return DKIM_STAT_NORESOURCE;
	}

	switch (sig->sig_signalg)
	{
	  case DKIM_SIGN_RSASHA1:
#ifdef SHA256_DIGEST_LENGTH
	  case DKIM_SIGN_RSASHA256:
#endif /* SHA256_DIGEST_LENGTH */
	  {
		struct dkim_rsa *rsa;

#ifdef SHA256_DIGEST_LENGTH
		assert(sig->sig_hashtype == DKIM_HASHTYPE_SHA1 ||
		       sig->sig_hashtype == DKIM_HASHTYPE_SHA256);
#else /* SHA256_DIGEST_LENGTH */
		assert(sig->sig_hashtype == DKIM_HASHTYPE_SHA1);
#endif /* SHA256_DIGEST_LENGTH */

		rsa = DKIM_MALLOC(dkim, sizeof(struct dkim_rsa));
		if (rsa == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           sizeof(struct dkim_rsa));
			return DKIM_STAT_NORESOURCE;
		}
		memset(rsa, '\0', sizeof(struct dkim_rsa));

		sig->sig_signature = (void *) rsa;
		sig->sig_keytype = DKIM_KEYTYPE_RSA;

		rsa->rsa_pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);

		if (rsa->rsa_pkey == NULL)
		{
			dkim_error(dkim, "PEM_read_bio_PrivateKey() failed");
			BIO_free(key);
			return DKIM_STAT_NORESOURCE;
		}

		rsa->rsa_rsa = EVP_PKEY_get1_RSA(rsa->rsa_pkey);
		if (rsa->rsa_rsa == NULL)
		{
			dkim_error(dkim, "EVP_PKEY_get1_RSA() failed");
			BIO_free(key);
			return DKIM_STAT_NORESOURCE;
		}

		rsa->rsa_keysize = RSA_size(rsa->rsa_rsa);
		rsa->rsa_pad = RSA_PKCS1_PADDING;
		rsa->rsa_rsaout = DKIM_MALLOC(dkim, rsa->rsa_keysize);
		if (rsa->rsa_rsaout == NULL)
		{
			dkim_error(dkim, "unable to allocate %d byte(s)",
			           rsa->rsa_keysize);
			RSA_free(rsa->rsa_rsa);
			rsa->rsa_rsa = NULL;
			BIO_free(key);
			return DKIM_STAT_NORESOURCE;
		}

		sig->sig_keybits = rsa->rsa_keysize * 8;

		break;
	  }

	  default:
		assert(0);
	}

	/* construct the DKIM signature header to be canonicalized */
	n = strlcpy(tmp, DKIM_SIGNHEADER ": ", sizeof tmp);

	ret = dkim_getsighdr(dkim, tmp + n, sizeof tmp - n,
	                     strlen(DKIM_SIGNHEADER) + 2);
	if (ret != DKIM_STAT_OK)
		return ret;

	len = strlen(tmp);

	if (len == DKIM_MAXHEADER)
	{
		dkim_error(dkim, "generated signature header too large");
		return DKIM_STAT_NORESOURCE;
	}

	hdr.hdr_text = tmp;
	hdr.hdr_colon = tmp + DKIM_SIGNHEADER_LEN;
	hdr.hdr_namelen = n - 2;
	hdr.hdr_textlen = len;
	hdr.hdr_flags = 0;
	hdr.hdr_next = NULL;

	/* canonicalize */
	dkim_canon_signature(dkim, &hdr);

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
	  case DKIM_SIGN_RSASHA1:
#ifdef SHA256_DIGEST_LENGTH
	  case DKIM_SIGN_RSASHA256:
#endif /* SHA256_DIGEST_LENGTH */
	  {
		int nid;
		struct dkim_rsa *rsa;

		rsa = (struct dkim_rsa *) sig->sig_signature;

		nid = NID_sha1;

#ifdef SHA256_DIGEST_LENGTH
		if (sig->sig_hashtype == DKIM_HASHTYPE_SHA256)
			nid = NID_sha256;
#endif /* SHA256_DIGEST_LENGTH */

		status = RSA_sign(nid, digest, diglen,
	                          rsa->rsa_rsaout, &l, rsa->rsa_rsa);
		if (status == 0 || l == 0)
		{
			RSA_free(rsa->rsa_rsa);
			rsa->rsa_rsa = NULL;
			BIO_free(key);
			dkim_error(dkim,
			           "signature generation failed (status %d, length %d)",
			           status, l);
			return DKIM_STAT_INTERNAL;
		}

		rsa->rsa_rsaoutlen = l;

		signature = rsa->rsa_rsaout;
		siglen = rsa->rsa_rsaoutlen;

		break;
	  }

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
		BIO_free(key);
		return DKIM_STAT_NORESOURCE;
	}
	memset(dkim->dkim_b64sig, '\0', dkim->dkim_b64siglen);

	status = dkim_base64_encode(signature, siglen, dkim->dkim_b64sig,
	                            dkim->dkim_b64siglen);

	BIO_free(key);

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

	if (dkim->dkim_state >= DKIM_STATE_EOM2)
		return DKIM_STAT_INVALID;
	if (dkim->dkim_state < DKIM_STATE_EOM1)
		dkim->dkim_state = DKIM_STATE_EOM1;

	if (dkim->dkim_chunkstate != DKIM_CHUNKSTATE_INIT &&
	    dkim->dkim_chunkstate != DKIM_CHUNKSTATE_DONE)
		return DKIM_STAT_INVALID;

	/* finalize body canonicalizations */
	(void) dkim_canon_closebody(dkim);

	dkim->dkim_bodydone = TRUE;

	if (dkim->dkim_sigcount == 0)
	{					/* unsigned */
		if (dkim->dkim_domain == NULL)
		{
			char *domain;
			char *user;

			hdr = dkim_get_header(dkim, DKIM_FROMHEADER,
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

			status = rfc2822_mailbox_split(hdr->hdr_colon + 1,
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
		    sig->sig_bodycanon->canon_length != (off_t) -1 &&
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
			break;

		  case DKIM_CBSTAT_REJECT:
			return DKIM_STAT_CBREJECT;

		  case DKIM_CBSTAT_TRYAGAIN:
			return DKIM_STAT_CBTRYAGAIN;

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

				/* pass and bh match? */
				if ((sig->sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
				    sig->sig_bh == DKIM_SIGBH_MATCH)
					break;
			}

			sig = NULL;
		}
	}

	/*
	**  If still none, we're going to fail so just use the
	**  first one.
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
dkim_new(DKIM_LIB *libhandle, const char *id, void *memclosure,
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
	new->dkim_querymethod = DKIM_QUERY_DEFAULT;
	new->dkim_mode = DKIM_MODE_UNKNOWN;
	new->dkim_state = DKIM_STATE_INIT;
	new->dkim_presult = DKIM_PRESULT_NONE;
#ifdef USE_UNBOUND
	new->dkim_dnssec_policy = DKIM_DNSSEC_UNKNOWN;
#endif /* USE_UNBOUND */
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

	/* initialize OpenSSL algorithms */
	OpenSSL_add_all_algorithms();

	/* copy the parameters */
	libhandle = (DKIM_LIB *) malloc(sizeof(struct dkim_lib));
	if (libhandle == NULL)
		return NULL;

	td = getenv("DKIM_TMPDIR");
	if (td == NULL || td[0] == '\0')
		td = DEFTMPDIR;

	libhandle->dkiml_signre = FALSE;
	libhandle->dkiml_skipre = FALSE;
	libhandle->dkiml_malloc = caller_mallocf;
	libhandle->dkiml_free = caller_freef;
	strlcpy(libhandle->dkiml_tmpdir, td, 
	        sizeof libhandle->dkiml_tmpdir);
	libhandle->dkiml_flags = DKIM_LIBFLAGS_DEFAULT;
	libhandle->dkiml_timeout = DEFTIMEOUT;
	libhandle->dkiml_senderhdrs = (u_char **) default_senderhdrs;
	libhandle->dkiml_alwayshdrs = NULL;
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

	libhandle->dkiml_key_lookup = NULL;
	libhandle->dkiml_policy_lookup = NULL;
	libhandle->dkiml_sig_handle = NULL;
	libhandle->dkiml_sig_handle_free = NULL;
	libhandle->dkiml_sig_tagvalues = NULL;
	libhandle->dkiml_prescreen = NULL;
	libhandle->dkiml_final = NULL;
	libhandle->dkiml_dns_callback = NULL;
	
#ifdef USE_UNBOUND
	/* initialize the unbound resolver */
	if (dkim_unbound_init(libhandle) != 0)
	{
		free(libhandle);
		return NULL;
	}
#endif /* USE_UNBOUND */

	/* initialize the resolver */
#if USE_ARLIB
	libhandle->dkiml_arlib = ar_init(NULL, NULL, NULL, 0);
	if (libhandle->dkiml_arlib == NULL)
	{
		free(libhandle);
		return NULL;
	}
# ifdef _FFR_DNS_UPGRADE
	libhandle->dkiml_arlibtcp = ar_init(NULL, NULL, NULL, AR_FLAG_USETCP);
	if (libhandle->dkiml_arlibtcp == NULL)
	{
		(void) ar_shutdown(libhandle->dkiml_arlib);
		free(libhandle);
		return NULL;
	}
# endif /* _FFR_DNS_UPGRADE */
#else /* USE_ARLIB */
	(void) res_init();
#endif /* USE_ARLIB */

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

#ifdef USE_ARLIB
	if (lib->dkiml_arlib != NULL)
		(void) ar_shutdown(lib->dkiml_arlib);

# ifdef _FFR_DNS_UPGRADE
	if (lib->dkiml_arlibtcp != NULL)
		(void) ar_shutdown(lib->dkiml_arlibtcp);
# endif /* _FFR_DNS_UPGRADE */
#endif /* USE_ARLIB */

#ifdef USE_UNBOUND
	(void) dkim_unbound_close(lib);
#endif /* USE_UNBOUND */

	if (lib->dkiml_skipre)
		(void) regfree(&lib->dkiml_skiphdrre);
	
	if (lib->dkiml_signre)
		(void) regfree(&lib->dkiml_hdrre);
	
	free((void *) lib);

	EVP_cleanup();
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
	char *new;
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
		flen = vsnprintf(dkim->dkim_error, dkim->dkim_errlen,
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
			strlcpy((u_char *) ptr,
			        lib->dkiml_tmpdir, len);
		}
		else if (ptr == NULL)
		{
			strlcpy(lib->dkiml_tmpdir, DEFTMPDIR,
			        sizeof lib->dkiml_tmpdir);
		}
		else
		{
			strlcpy(lib->dkiml_tmpdir, (u_char *) ptr,
			        sizeof lib->dkiml_tmpdir);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_FIXEDTIME:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_fixedtime)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_fixedtime, len);
		}
		else
		{
			memcpy(&lib->dkiml_fixedtime, ptr, len);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_SIGNATURETTL:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_sigttl)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_sigttl, len);
		}
		else
		{
			memcpy(&lib->dkiml_sigttl, ptr, len);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_CLOCKDRIFT:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_clockdrift)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_clockdrift, len);
		}
		else
		{
			memcpy(&lib->dkiml_clockdrift, ptr, len);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_FLAGS:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_flags)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_flags, len);
		}
		else
		{
			memcpy(&lib->dkiml_flags, ptr, len);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_TIMEOUT:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (len != sizeof lib->dkiml_timeout)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_timeout, len);
		}
		else
		{
			memcpy(&lib->dkiml_timeout, ptr, len);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_SENDERHDRS:
		if (len != sizeof lib->dkiml_senderhdrs)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_senderhdrs, len);
		}
		else if (ptr == NULL)
		{
			lib->dkiml_senderhdrs = (u_char **) default_senderhdrs;
		}
		else
		{
			lib->dkiml_senderhdrs = (u_char **) ptr;
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_ALWAYSHDRS:
		if (len != sizeof lib->dkiml_alwayshdrs)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			memcpy(ptr, &lib->dkiml_alwayshdrs, len);
		}
		else if (ptr == NULL)
		{
			lib->dkiml_alwayshdrs = NULL;
		}
		else
		{
			lib->dkiml_alwayshdrs = (u_char **) ptr;
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
			lib->dkiml_mbs = NULL;
		}
		else
		{
			lib->dkiml_mbs = (u_char **) ptr;
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
			char buf[BUFRSZ + 1];

			if (lib->dkiml_signre)
			{
				(void) regfree(&lib->dkiml_hdrre);
				lib->dkiml_signre = FALSE;
			}

			memset(buf, '\0', sizeof buf);

			hdrs = (u_char **) ptr;

			(void) strlcpy(buf, "^(", sizeof buf);

			if (!dkim_hdrlist(buf, sizeof buf,
			                  (u_char **) required_signhdrs, TRUE))
				return DKIM_STAT_INVALID;
			if (!dkim_hdrlist(buf, sizeof buf, hdrs, FALSE))
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

			if (!dkim_hdrlist(buf, sizeof buf, hdrs, TRUE))
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
		{
			memcpy(ptr, &lib->dkiml_querymethod, len);
		}
		else
		{
			memcpy(&lib->dkiml_querymethod, ptr, len);
		}
		return DKIM_STAT_OK;

	  case DKIM_OPTS_QUERYINFO:
		if (ptr == NULL)
			return DKIM_STAT_INVALID;

		if (op == DKIM_OP_GETOPT)
		{
			strlcpy(ptr, lib->dkiml_queryinfo, len);
		}
		else
		{
			strlcpy(lib->dkiml_queryinfo, ptr,
			        sizeof lib->dkiml_queryinfo);
		}
		return DKIM_STAT_OK;

	  default:
		return DKIM_STAT_INVALID;
	}

	/* to silence -Wall */
	return DKIM_STAT_INTERNAL;
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

	/* blast the headers */
	if (dkim->dkim_hhead != NULL)
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
	if (dkim->dkim_sethead != NULL)
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

			CLOBBER(dkim->dkim_siglist[c]->sig_key);
			CLOBBER(dkim->dkim_siglist[c]->sig_sig);
			if (dkim->dkim_siglist[c]->sig_keytype == DKIM_KEYTYPE_RSA)
			{
				struct dkim_rsa *rsa;

				rsa = dkim->dkim_siglist[c]->sig_signature;
				if (rsa != NULL)
				{
					EVP_CLOBBER(rsa->rsa_pkey);
					RSA_CLOBBER(rsa->rsa_rsa);
					CLOBBER(rsa->rsa_rsaout);
				}
			}
			CLOBBER(dkim->dkim_siglist[c]->sig_signature);
			CLOBBER(dkim->dkim_siglist[c]);
		}

		CLOBBER(dkim->dkim_siglist);
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
dkim_sign(DKIM_LIB *libhandle, const char *id, void *memclosure,
          const dkim_sigkey_t secretkey, const char *selector,
          const char *domain, dkim_canon_t hdrcanonalg,
	  dkim_canon_t bodycanonalg, dkim_alg_t signalg,
          off_t length, DKIM_STAT *statp)
{
	DKIM *new;

	assert(libhandle != NULL);
	assert(secretkey != NULL);
	assert(selector != NULL);
	assert(domain != NULL);
	assert(hdrcanonalg == DKIM_CANON_SIMPLE ||
	       hdrcanonalg == DKIM_CANON_RELAXED);
	assert(bodycanonalg == DKIM_CANON_SIMPLE ||
	       bodycanonalg == DKIM_CANON_RELAXED);
#ifdef SHA256_DIGEST_LENGTH
	assert(signalg == DKIM_SIGN_RSASHA1 || signalg == DKIM_SIGN_RSASHA256);
#else /* SHA256_DIGEST_LENGTH */
	assert(signalg == DKIM_SIGN_RSASHA1);
#endif /* SHA256_DIGEST_LENGTH */
	assert(statp != NULL);

	new = dkim_new(libhandle, id, memclosure, hdrcanonalg, bodycanonalg,
	               signalg, statp);

	if (new != NULL)
	{
		new->dkim_mode = DKIM_MODE_SIGN;

		new->dkim_keylen = strlen((const char *) secretkey);
		new->dkim_key = (unsigned char *) DKIM_MALLOC(new,
		                                              new->dkim_keylen + 1);

		if (new->dkim_key == NULL)
		{
			*statp = DKIM_STAT_NORESOURCE;
			dkim_free(new);
			return NULL;
		}

		memcpy(new->dkim_key, (char *) secretkey,
		       new->dkim_keylen + 1);

		new->dkim_selector = dkim_strdup(new, selector, 0);
		new->dkim_domain = dkim_strdup(new, domain, 0);
		if (length == (off_t) -1)
			new->dkim_signlen = ULONG_MAX;
		else
			new->dkim_signlen = length;
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
dkim_verify(DKIM_LIB *libhandle, const char *id, void *memclosure,
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
**  DKIM_POLICY -- parse policy associated with the sender's domain
**
**  Parameters:
**  	dkim -- DKIM handle
**  	pcode -- discovered policy (returned)
**  	pstate -- state, for re-entrancy (updated; can be NULL)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_policy(DKIM *dkim, dkim_policy_t *pcode, DKIM_PSTATE *pstate)
{
	int wlen;
	int qstatus = NOERROR;
	unsigned int pflags;
	DKIM_STAT status;
	dkim_policy_t policy = DKIM_POLICY_NONE;
	char query[DKIM_MAXHOSTNAMELEN + 1];

	assert(dkim != NULL);

	/* fail for signing handles */
	if (dkim->dkim_mode == DKIM_MODE_SIGN)
		return DKIM_STAT_INVALID;

	/* fail if no domain could be determined */
	if (dkim->dkim_domain == NULL)
		return DKIM_STAT_SYNTAX;

	/* initialize */
	dkim->dkim_presult = DKIM_PRESULT_NONE;
	if (pstate != NULL)
	{
		qstatus = pstate->ps_qstatus;
		policy = pstate->ps_policy;
		pflags = pstate->ps_pflags;
	}

	/*
	**  Apply draft-ietf-dkim-ssp-04 sender signing policy algorithm:
	*/

	/*
	**  Verify Domain Scope:   An ADSP verifier implementation MUST
	**  determine whether a given Author Domain is within scope for
	**  ADSP.  Given the background in Section 3.1 the verifier MUST
	**  decide which degree of over-approximation is acceptable.  The
	**  verifier MUST return an appropriate error result for Author
	**  Domains that are outside the scope of ADSP.
	**
	**  The host MUST perform a DNS query for a record corresponding to
	**  the Author Domain (with no prefix).  The type of the query can
	**  be of any type, since this step is only to determine if the
	**  domain itself exists in DNS.  This query MAY be done in parallel
	**  with the query to fetch the Named ADSP Record.  If the result of
	**  this query is that the Author domain does not exist in the DNS
	**  (often called an "NXDOMAIN" error), the algorithm MUST terminate
	**  with an error indicating that the domain is out of scope.
	**
	**  NON-NORMATIVE DISCUSSION: Any resource record type could be used
	**  for this query since the existence of a resource record of any
	**  type will prevent an "NXDOMAIN" error.  MX is a reasonable choice
	**  for this purpose because this record type is thought to be
	**  the most common for domains used in e-mail, and will therefore
	**  produce a result which can be more readily cached than a negative
	**  result.
	**
	**  If the domain does exist, the verifier MAY make more extensive
	**  checks to verify the existence of the domain, such as the ones
	**  described in Section 5 of [RFC2821].  If those checks indicate
	**  that the Author domain does not exist for mail, e.g., the domain
	**  has no MX, A, or AAAA record, the verifier SHOULD terminate with
	**  an error indicating that the domain is out of scope.
	*/

	if (pstate == NULL || pstate->ps_state < 1)
	{
		status = dkim_get_policy(dkim, dkim->dkim_domain, TRUE,
		                         &qstatus, &policy, &pflags);
		if (status != DKIM_STAT_OK)
		{
			if (status == DKIM_STAT_CBTRYAGAIN && pstate != NULL)
			{
				pstate->ps_qstatus = qstatus;
				pstate->ps_policy = policy;
				pstate->ps_pflags = pflags;
			}

			return status;
		}

		if (pstate != NULL)
			pstate->ps_state = 1;
	}

	if (qstatus == NXDOMAIN)
	{
		dkim->dkim_presult = DKIM_PRESULT_NXDOMAIN;
		if (pcode != NULL)
			*pcode = policy;
		return DKIM_STAT_OK;
	}

	/*
	**  Fetch Named ADSP Record:   The host MUST query DNS for a TXT
	**  record corresponding to the Author Domain prefixed by
	**  "_adsp._domainkey." (note the trailing dot).
	**
	**  If the result of this query is a "NOERROR" response with an
	**  answer which is a valid ADSP record, use that record, and the
	**  algorithm terminates.
	**
	**  If a query results in a "SERVFAIL" error response, the algorithm
	**  terminates without returning a result; possible actions include
	**  queuing the message or returning an SMTP error indicating a
	**  temporary failure.
	*/

	if (pstate == NULL || pstate->ps_state < 2)
	{
		wlen = snprintf(query, sizeof query, "%s.%s.%s",
		                DKIM_DNSPOLICYNAME, DKIM_DNSKEYNAME,
		                dkim->dkim_domain);
		if (wlen >= sizeof query)
		{
			dkim_error(dkim, "policy query name overflow");
			return DKIM_STAT_NORESOURCE;
		}

		status = dkim_get_policy(dkim, query, FALSE,
		                         &qstatus, &policy, &pflags);
		if (status != DKIM_STAT_OK)
		{
			if (status == DKIM_STAT_CBTRYAGAIN && pstate != NULL)
			{
				pstate->ps_qstatus = qstatus;
				pstate->ps_policy = policy;
				pstate->ps_pflags = pflags;
			}

			return status;
		}

		if (pstate != NULL)
			pstate->ps_state = 2;
	}

	if (qstatus == NOERROR)
		dkim->dkim_presult = DKIM_PRESULT_AUTHOR;
	if (pcode != NULL)
		*pcode = policy;

	return DKIM_STAT_OK;
}

#ifdef USE_UNBOUND
/*
**  DKIM_POLICY_GETDNSSEC -- retrieve DNSSEC results for a policy
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_DNSSEC_* constant.
*/

u_int
dkim_policy_getdnssec(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_dnssec_policy;
}
#endif /* USE_UNBOUND */

/*
**  DKIM_POLICY_GETREPORTINFO -- retrieve reporting information from policy
**
**  Parameters:
**  	dkim -- DKIM handle
**  	addr -- address buffer (or NULL)
**  	addrlen -- size of addr
**  	fmt -- format buffer (or NULL)
**  	fmtlen -- size of fmt
**  	opts -- options buffer (or NULL)
**  	optslen -- size of opts
**  	smtp -- SMTP prefix buffer (or NULL)
**  	smtplen -- size of smtp
**  	interval -- requested report interval (or NULL)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_policy_getreportinfo(DKIM *dkim,
                          u_char *addr, size_t addrlen,
                          u_char *fmt, size_t fmtlen,
                          u_char *opts, size_t optslen,
                          u_char *smtp, size_t smtplen,
                          u_int *interval)
{
	u_char *p;
	DKIM_SET *set;

	assert(dkim != NULL);

	if (dkim->dkim_state != DKIM_STATE_EOM2 ||
	    dkim->dkim_mode != DKIM_MODE_VERIFY)
		return DKIM_STAT_INVALID;

	set = dkim_set_first(dkim, DKIM_SETTYPE_POLICY);
	if (set == NULL)
		return DKIM_STAT_CANTVRFY;

	if (addr != NULL)
	{
		p = dkim_param_get(set, "r");
		if (p != NULL)
		{
			memset(addr, '\0', addrlen);
			(void) dkim_qp_decode(p, addr, addrlen);
			p = strchr(addr, '@');
			if (p != NULL)
				*p = '\0';
		}
	}

	if (fmt != NULL)
	{
		p = dkim_param_get(set, "rf");
		if (p != NULL)
			strlcpy(fmt, p, fmtlen);
	}

	if (opts != NULL)
	{
		p = dkim_param_get(set, "ro");
		if (p != NULL)
			strlcpy(opts, p, optslen);
	}

	if (smtp != NULL)
	{
		p = dkim_param_get(set, "rs");
		if (p != NULL)
		{
			memset(smtp, '\0', smtplen);
			(void) dkim_qp_decode(p, smtp, smtplen);
		}
	}

	if (interval != NULL)
	{
		p = dkim_param_get(set, "ri");
		if (p != NULL)
		{
			u_int out;
			char *q;

			out = strtoul(p, &q, 10);
			if (*q == '\0')
				*interval = out;
		}
	}

	return DKIM_STAT_OK;
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
	int rsastat;
	size_t diglen = 0;
	BIO *key;
	u_char *digest = NULL;
	struct dkim_rsa *rsa;

	assert(dkim != NULL);
	assert(sig != NULL);

	/* skip it if we're supposed to ignore it */
	if ((sig->sig_flags & DKIM_SIGFLAG_IGNORE) != 0)
		return DKIM_STAT_OK;

	/* skip it if there was a syntax or other error */
	if (sig->sig_error != DKIM_SIGERROR_UNKNOWN)
		return DKIM_STAT_OK;

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
		status = dkim_get_key(dkim, sig);
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

		/* load the public key */
		key = BIO_new_mem_buf(sig->sig_key, sig->sig_keylen);
		if (key == NULL)
		{
			dkim_error(dkim, "BIO_new_mem_buf() failed");
			return DKIM_STAT_NORESOURCE;
		}

		/* set up to verify */
		if (sig->sig_signature == NULL)
		{
			rsa = DKIM_MALLOC(dkim, sizeof(struct dkim_rsa));
			if (rsa == NULL)
			{
				dkim_error(dkim,
				           "unable to allocate %d byte(s)",
				           sizeof(struct dkim_rsa));
				BIO_free(key);
				return DKIM_STAT_NORESOURCE;
			}

			sig->sig_signature = rsa;
		}
		else
		{
			rsa = sig->sig_signature;
		}
		memset(rsa, '\0', sizeof(struct dkim_rsa));

		rsa->rsa_pkey = d2i_PUBKEY_bio(key, NULL);
		if (rsa->rsa_pkey == NULL)
		{
			dkim_error(dkim, "s=%s d=%s: d2i_PUBKEY_bio() failed",
			           dkim_sig_getselector(sig),
			           dkim_sig_getdomain(sig));
			BIO_free(key);

			sig->sig_error = DKIM_SIGERROR_KEYDECODE;

			return DKIM_STAT_OK;
		}

		/* set up the RSA object */
		rsa->rsa_rsa = EVP_PKEY_get1_RSA(rsa->rsa_pkey);
		if (rsa->rsa_rsa == NULL)
		{
			dkim_error(dkim,
			           "s=%s d=%s: EVP_PKEY_get1_RSA() failed",
			           dkim_sig_getselector(sig),
			           dkim_sig_getdomain(sig));
			BIO_free(key);

			sig->sig_error = DKIM_SIGERROR_KEYDECODE;

			return DKIM_STAT_OK;
		}

		rsa->rsa_keysize = RSA_size(rsa->rsa_rsa);
		rsa->rsa_pad = RSA_PKCS1_PADDING;

		rsa->rsa_rsain = sig->sig_sig;
		rsa->rsa_rsainlen = sig->sig_siglen;

		sig->sig_keybits = 8 * rsa->rsa_keysize;

		nid = NID_sha1;

#ifdef SHA256_DIGEST_LENGTH
		if (sig->sig_hashtype == DKIM_HASHTYPE_SHA256)
			nid = NID_sha256;
#endif /* SHA256_DIGEST_LENGTH */

		rsastat = RSA_verify(nid, digest, diglen, rsa->rsa_rsain,
	                    	rsa->rsa_rsainlen, rsa->rsa_rsa);
		if (rsastat == 1)
			sig->sig_flags |= DKIM_SIGFLAG_PASSED;
		else
			sig->sig_error = DKIM_SIGERROR_BADSIG;

		sig->sig_flags |= DKIM_SIGFLAG_PROCESSED;

		BIO_free(key);
		RSA_free(rsa->rsa_rsa);
		rsa->rsa_rsa = NULL;
	}

	/* do the body hash check if possible */
	if (dkim->dkim_bodydone && sig->sig_bh == DKIM_SIGBH_UNTESTED &&
	    (sig->sig_flags & DKIM_SIGFLAG_PASSED) != 0)
	{
		u_char *bhash;
		u_char b64buf[BUFRSZ];

		memset(b64buf, '\0', sizeof b64buf);

		dkim_canon_getfinal(sig->sig_bodycanon, &digest, &diglen);

		bhash = dkim_param_get(sig->sig_taglist, "bh");

		dkim_base64_encode(digest, diglen, b64buf, sizeof b64buf);

		if (strcmp(bhash, b64buf) == 0)
			sig->sig_bh = DKIM_SIGBH_MATCH;
		else
			sig->sig_bh = DKIM_SIGBH_MISMATCH;
	}

	/*
	**  Fail if t=s was present in the key and the i= and d= domains
	**  don't match.
	*/

	if ((sig->sig_flags & DKIM_SIGFLAG_NOSUBDOMAIN) != 0)
	{
		char *d;
		char *i;

		d = dkim_param_get(sig->sig_taglist, "d");
		i = dkim_param_get(sig->sig_taglist, "i");

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

	if (sig->sig_error == DKIM_SIGERROR_UNKNOWN &&
	    sig->sig_bh != DKIM_SIGBH_UNTESTED)
		sig->sig_error = DKIM_SIGERROR_OK;

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
dkim_ohdrs(DKIM *dkim, DKIM_SIGINFO *sig, char **ptrs, int *pcnt)
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
	z = dkim_param_get(sig->sig_taglist, "z");
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
	strlcpy(dkim->dkim_zdecode, z, strlen(z));

	/* decode */
	for (ch = strtok_r(z, "|", &last);
	     ch != NULL;
	     ch = strtok_r(NULL, "|", &last))
	{
		for (p = ch, q = ch; *p != '\0'; p++)
		{
			if (*p == '=')
			{
				char c;

				if (!isxdigit(*(p + 1)) || !isxdigit(*(p + 2)))
					return DKIM_STAT_INVALID;

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

#ifdef _FFR_DIFFHEADERS

# if !defined(TRE_APPROX) || (TRE_APPROX == 0)
#  error _FFR_DIFFHEADERS requires approximate regular expression matching
# endif /* !defined(TRE_APPROX) || (TRE_APPROX == 0) */

/*
**  DKIM_DIFFHEADERS -- compare original headers with received headers
**
**  Parameters:
**  	dkim -- DKIM handle
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
dkim_diffheaders(DKIM *dkim, int maxcost, char **ohdrs, int nohdrs,
                 struct dkim_hdrdiff **out, int *nout)
{
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

	for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		memset(restr, '\0', sizeof restr);

		end = restr + sizeof restr;

		for (p = hdr->hdr_text, q = restr;
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

		status = regcomp(&re, restr, REG_NOSUB);
		if (status != 0)
		{
			char err[BUFRSZ + 1];

			memset(err, '\0', sizeof err);

			(void) regerror(status, &re, err, sizeof err);

			dkim_error(dkim, err);

			if (diffs != NULL)
				dkim_mfree(lib, cls, diffs);

			return DKIM_STAT_INTERNAL;
		}

		for (c = 0; c < nohdrs; c++)
		{
			if (strcmp(ohdrs[c], hdr->hdr_text) == 0)
				continue;

			status = regaexec(&re, ohdrs[c], &matches, params, 0);

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

		regfree(&re);
	}

	*out = diffs;
	*nout = n;

	return DKIM_STAT_OK;
}
#endif /* _FFR_DIFFHEADERS */

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
	u_char *end = NULL;
	struct dkim_header *h;

	assert(dkim != NULL);
	assert(hdr != NULL);
	assert(len != 0);

	if (dkim->dkim_state > DKIM_STATE_HEADER)
		return DKIM_STAT_INVALID;
	dkim->dkim_state = DKIM_STATE_HEADER;

	colon = memchr(hdr, ':', len);
	if (colon != NULL)
	{
		end = colon;

		while (end > hdr && isascii(*(end - 1)) && isspace(*(end - 1)))
			end--;
	}

	/* see if this is one we should skip */
	if (dkim->dkim_mode == DKIM_MODE_SIGN &&
	    dkim->dkim_libhandle->dkiml_skipre)
	{
		int status;
		char name[DKIM_MAXHEADER + 1];

		strlcpy(name, hdr, sizeof name);
		if (end != NULL)
			name[end - hdr] = '\0';

		status = regexec(&dkim->dkim_libhandle->dkiml_skiphdrre,
		                 name, 0, NULL, 0);

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

	h->hdr_text = dkim_strdup(dkim, hdr, len);
	if (h->hdr_text == NULL)
		return DKIM_STAT_NORESOURCE;
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
		    strncasecmp(hdr, DKIM_SIGNHEADER,
		                DKIM_SIGNHEADER_LEN) == 0)
		{
			DKIM_STAT status;
			size_t plen;

			plen = len - (h->hdr_colon - h->hdr_text) - 1;
			status = dkim_process_set(dkim, DKIM_SETTYPE_SIGNATURE,
			                          h->hdr_colon + 1, plen, h,
			                          FALSE);

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
#ifdef _FFR_PARSE_TIME
	struct dkim_header *hdr;
#endif /* _FFR_PARSE_TIME */

	assert(dkim != NULL);

#ifdef _FFR_PARSE_TIME
#define RFC2822DATE	"%a, %d %b %Y %H:%M:%S %z"
/* # define RFC2822DATE	"%a" */
	/* store the Date: value for possible later scrutiny */
	hdr = dkim_get_header(dkim, DKIM_DATEHEADER, DKIM_DATEHEADER_LEN, 0);
	if (hdr != NULL)
	{
		char *colon;

		colon = hdr->hdr_colon;
		if (colon != NULL)
		{
			char *p;
			struct tm tm;

			colon++;
			while (isascii(*colon) && isspace(*colon))
				colon++;

			p = strptime(colon, RFC2822DATE, &tm);
			if (p != NULL)
				dkim->dkim_msgdate = mktime(&tm);
		}
	}
#endif /* _FFR_PARSE_TIME */

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

	if (dkim->dkim_state > DKIM_STATE_BODY)
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
	DKIM_STAT status;
	unsigned char *p;
	unsigned char *end;

	assert(dkim != NULL);

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
				if (status != DKIM_STAT_OK)
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
			dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
			if (*p == '\r')
				dkim->dkim_chunksm = 1;
			break;

		  case 1:
			dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
			if (*p == '\n')
				dkim->dkim_chunksm = 2;
			else
				dkim->dkim_chunksm = 0;
			break;
			
		  case 2:
			if (DKIM_ISLWSP(*p))
			{
				dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
				dkim->dkim_chunksm = 0;
			}
			else if (*p == '\r')
			{
				dkim->dkim_chunksm = 3;
			}
			else
			{
				status = dkim_header(dkim,
				                     dkim_dstring_get(dkim->dkim_hdrbuf),
				                     dkim_dstring_len(dkim->dkim_hdrbuf) - 2);
				if (status != DKIM_STAT_OK)
					return status;

				dkim_dstring_blank(dkim->dkim_hdrbuf);
				dkim_dstring_cat1(dkim->dkim_hdrbuf, *p);
				dkim->dkim_chunksm = 0;
			}
			break;
				
		  case 3:
			if (*p == '\n')
			{
				if (dkim_dstring_len(dkim->dkim_hdrbuf) > 0)
				{
					status = dkim_header(dkim,
					                     dkim_dstring_get(dkim->dkim_hdrbuf),
					                     dkim_dstring_len(dkim->dkim_hdrbuf) - 2);
					if (status != DKIM_STAT_OK)
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
				if (status != DKIM_STAT_OK)
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
	return dkim_process_set(dkim, DKIM_SETTYPE_KEY, str, len, NULL, TRUE);
}

/*
**  DKIM_POLICY_SYNTAX -- process a policy record parameter set
**                        for valid syntax
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
dkim_policy_syntax(DKIM *dkim, u_char *str, size_t len)
{
	return dkim_process_set(dkim, DKIM_SETTYPE_POLICY, str, len,
	                        NULL, TRUE);
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
	                        NULL, TRUE);
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
**  	Per RFC4871 section 3.7, the signature header returned here does
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

	tmpbuf = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
	if (tmpbuf == NULL)
		return DKIM_STAT_NORESOURCE;

	if (dkim->dkim_hdrbuf == NULL)
	{
		dkim->dkim_hdrbuf = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
		if (dkim->dkim_hdrbuf == NULL)
		{
			dkim_dstring_free(tmpbuf);
			return DKIM_STAT_NORESOURCE;
		}
	}
	else
	{
		dkim_dstring_blank(dkim->dkim_hdrbuf);
	}

	/* compute and extract the signature header */
	len = dkim_gensighdr(dkim, sig, tmpbuf, DELIMITER);

	if (dkim->dkim_b64sig != NULL)
		dkim_dstring_cat(tmpbuf, dkim->dkim_b64sig);

	if (dkim->dkim_margin == 0)
	{
		_Bool first = TRUE;

		for (pv = strtok_r(dkim_dstring_get(tmpbuf), DELIMITER, &ctx);
		     pv != NULL;
		     pv = strtok_r(NULL, DELIMITER, &ctx))
		{
			if (!first)
				dkim_dstring_cat(dkim->dkim_hdrbuf, " ");

			dkim_dstring_cat(dkim->dkim_hdrbuf, pv);

			first = FALSE;
		}
	}
	else
	{
		_Bool first = TRUE;
		_Bool forcewrap;
		char *p;
		char *q;
		char *end;
		char which[MAXTAGNAME + 1];

		len = initial;
		end = which + MAXTAGNAME;

		for (pv = strtok_r(dkim_dstring_get(tmpbuf), DELIMITER, &ctx);
		     pv != NULL;
		     pv = strtok_r(NULL, DELIMITER, &ctx))
		{
			for (p = pv, q = which; *p != '=' && q <= end; p++, q++)
			{
				*q = *p;
				*(q + 1) = '\0';
			}

			/* force wrapping of "b=" ? */
			forcewrap = FALSE;
			if (sig->sig_keytype == DKIM_KEYTYPE_RSA)
			{
				u_int siglen;

				siglen = BASE64SIZE(sig->sig_keybits / 8);
				if (strcmp(which, "b") == 0 &&
				    len + strlen(which) + siglen + 1 >= dkim->dkim_margin)
					forcewrap = TRUE;
			}

			if (len == 0 || first)
			{
				dkim_dstring_cat(dkim->dkim_hdrbuf, pv);
				len += strlen(pv);
				first = FALSE;
			}
			else if (forcewrap ||
			         len + strlen(pv) > dkim->dkim_margin)
			{
				forcewrap = FALSE;
				dkim_dstring_cat(dkim->dkim_hdrbuf, "\r\n\t");
				len = 8;

				if (strcmp(which, "h") == 0)
				{			/* break at colons */
					_Bool ifirst = TRUE;
					char *tmp;
					char *ctx2;

					for (tmp = strtok_r(pv, ":", &ctx2);
					     tmp != NULL;
					     tmp = strtok_r(NULL, ":", &ctx2))
					{
						if (ifirst)
						{
							dkim_dstring_cat(dkim->dkim_hdrbuf,
							                 pv);
							len += strlen(pv);
							ifirst = FALSE;
						}
						else if (len + strlen(tmp) + 1 > dkim->dkim_margin)
						{
							dkim_dstring_cat(dkim->dkim_hdrbuf,
							                 ":");
							len += 1;
							dkim_dstring_cat(dkim->dkim_hdrbuf,
							                 "\r\n\t ");
							len = 9;
							dkim_dstring_cat(dkim->dkim_hdrbuf,
							                 tmp);
							len += strlen(tmp);
						}
						else
						{
							dkim_dstring_cat(dkim->dkim_hdrbuf,
							                 ":");
							len += 1;
							dkim_dstring_cat(dkim->dkim_hdrbuf,
							                 tmp);
							len += strlen(tmp);
						}
					}

				}
				else if (strcmp(which, "b") == 0 ||
				         strcmp(which, "bh") == 0 ||
				         strcmp(which, "z") == 0)
				{			/* break at margins */
					_Bool more;
					int offset;
					char *x;

					offset = strlen(which) + 1;

					dkim_dstring_cat(dkim->dkim_hdrbuf,
					                 which);
					dkim_dstring_cat(dkim->dkim_hdrbuf,
					                 "=");

					len += offset;

					for (x = pv + offset; *x != '\0'; x++)
					{
						more = (*(x + 1) != '\0');

						dkim_dstring_cat1(dkim->dkim_hdrbuf,
						                  *x);
						len++;

						if (len >= dkim->dkim_margin &&
						    more)
						{
							dkim_dstring_cat(dkim->dkim_hdrbuf,
							                 "\r\n\t ");
							len = 9;
						}
					}
				}
				else
				{			/* break at delimiter */
					dkim_dstring_cat(dkim->dkim_hdrbuf,
					                 pv);
					len += strlen(pv);
				}
			}
			else
			{
				if (!first)
				{
					dkim_dstring_cat(dkim->dkim_hdrbuf,
					                 " ");
					len += 1;
				}

				first = FALSE;
				dkim_dstring_cat(dkim->dkim_hdrbuf, pv);
				len += strlen(pv);
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
		return DKIM_STAT_NORESOURCE;

	strlcpy(buf, p, buflen);

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
dkim_sig_hdrsigned(DKIM_SIGINFO *sig, char *hdr)
{
	size_t len;
	char *c1 = NULL;
	char *c2 = NULL;
	char *p;
	char *hdrlist;
	char *start;

	assert(sig != NULL);
	assert(hdr != NULL);

	hdrlist = dkim_param_get(sig->sig_taglist, "h");
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

				if (strncasecmp(hdr, start, len) == 0)
					return TRUE;
			}
			else
			{
				if (strcasecmp(hdr, hdrlist) == 0)
					return TRUE;
			}

			break;
		}

		if (len != -1)
		{
			if (strncasecmp(hdr, start, len) == 0)
				return TRUE;
		}
	}

	return FALSE;
}

#ifdef USE_UNBOUND
/*
**  DKIM_SIG_GETDNSSEC -- retrieve DNSSEC results for a signature
**
**  Parameters:
**  	sig -- DKIM_SIGINFO handle
**
**  Return value:
**  	A DKIM_DNSSEC_* constant.
*/

u_int
dkim_sig_getdnssec(DKIM_SIGINFO *sig)
{
	assert(sig != NULL);

	return sig->sig_dnssec_key;
}
#endif /* USE_UNBOUND */

/*
**  DKIM_SIG_GETREPORTINFO -- retrieve reporting information from a key
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	hfd -- descriptor to canonicalized header (or NULL) (returned)
**  	bfd -- descriptor to canonicalized body (or NULL) (returned)
**  	addr -- address buffer (or NULL)
**  	addrlen -- size of addr
**  	fmt -- format buffer (or NULL)
**  	fmtlen -- size of fmt
**  	opts -- options buffer (or NULL)
**  	optslen -- size of opts
**  	smtp -- SMTP reply text buffer (or NULL)
**  	smtplen -- size of smtp
**  	interval -- requested reporting interval (or NULL)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_sig_getreportinfo(DKIM *dkim, DKIM_SIGINFO *sig,
                       int *hfd, int *bfd,
                       u_char *addr, size_t addrlen,
                       u_char *fmt, size_t fmtlen,
                       u_char *opts, size_t optslen,
                       u_char *smtp, size_t smtplen,
                       u_int *interval)
{
	u_char *p;
	DKIM_SET *set;

	assert(dkim != NULL);
	assert(sig != NULL);

	if (dkim->dkim_state != DKIM_STATE_EOM2 ||
	    dkim->dkim_mode != DKIM_MODE_VERIFY)
		return DKIM_STAT_INVALID;

	set = sig->sig_keytaglist;
	if (set == NULL)
		return DKIM_STAT_INTERNAL;

	if (addr != NULL)
	{
		p = dkim_param_get(set, "r");
		if (p != NULL)
		{
			memset(addr, '\0', addrlen);
			(void) dkim_qp_decode(p, addr, addrlen);
			p = strchr(addr, '@');
			if (p != NULL)
				*p = '\0';
		}
	}

	if (fmt != NULL)
	{
		p = dkim_param_get(set, "rf");
		if (p != NULL)
			strlcpy(fmt, p, fmtlen);
	}

	if (opts != NULL)
	{
		p = dkim_param_get(set, "ro");
		if (p != NULL)
			strlcpy(opts, p, optslen);
	}

	if (smtp != NULL)
	{
		p = dkim_param_get(set, "rs");
		if (p != NULL)
		{
			memset(smtp, '\0', smtplen);
			(void) dkim_qp_decode(p, smtp, smtplen);
		}
	}

	if (interval != NULL)
	{
		p = dkim_param_get(set, "ri");
		if (p != NULL)
		{
			u_int out;
			char *q;

			out = strtoul(p, &q, 10);
			if (*q == '\0')
				*interval = out;
		}
	}

	if (sig->sig_hdrcanon != NULL)
	{
		switch (sig->sig_hashtype)
		{
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

#ifdef SHA256_DIGEST_LENGTH
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
#endif /* SHA256_DIGEST_LENGTH */
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
dkim_sig_getidentity(DKIM *dkim, DKIM_SIGINFO *sig, char *val, size_t vallen)
{
	int len;
	char *param;
	struct dkim_set *set;

	assert(dkim != NULL);
	assert(val != NULL);
	assert(vallen != 0);

	if (sig == NULL)
	{
		sig = dkim->dkim_signature;
		if (sig == NULL)
			return DKIM_STAT_INVALID;
	}

	set = sig->sig_taglist;

	param = dkim_param_get(set, "i");
	if (param == NULL)
	{
		param = dkim_param_get(set, "d");
		if (param == NULL)
			return DKIM_STAT_INTERNAL;

		len = snprintf(val, vallen, "@%s", param);

		return (len < vallen ? DKIM_STAT_OK : DKIM_STAT_NORESOURCE);
	}
	else
	{
		len = dkim_qp_decode(param, val, vallen);

		return (len < vallen ? DKIM_STAT_OK : DKIM_STAT_NORESOURCE);
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
dkim_sig_getcanonlen(DKIM *dkim, DKIM_SIGINFO *sig, off_t *msglen,
                     off_t *canonlen, off_t *signlen)
{
	assert(dkim != NULL);
	assert(sig != NULL);

	if (msglen != NULL)
		*msglen = dkim->dkim_bodylen;

	if (canonlen != NULL)
		*canonlen = sig->sig_bodycanon->canon_wrote;

	if (signlen != NULL)
		*signlen = sig->sig_bodycanon->canon_length;

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
**  	An unsigned integer which is one of the DKIM_SIGBH_* constants
**  	indicating the current state of "bh" evaluation of the signature.
*/

unsigned int
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

	if (sig->sig_keybits == 0)
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
dkim_sig_getsigntime(DKIM_SIGINFO *sig, time_t *when)
{
	assert(sig != NULL);
	assert(when != NULL);

	if (sig->sig_timestamp == 0)
		return DKIM_STAT_INVALID;

	*when = (time_t) sig->sig_timestamp;

	return DKIM_STAT_OK;
}

#ifdef _FFR_STATS
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
#endif /* _FFR_STATS */

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
dkim_set_signer(DKIM *dkim, const char *signer)
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

	strlcpy(dkim->dkim_signer, signer, MAXADDRESS + 1);

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

#ifdef _FFR_BODYLENGTH_DB
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
#endif /* _FFR_BODYLENGTH_DB */

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
**  DKIM_GETPRESULT -- retrieve policy result
**
**  Parameters:
**  	dkim -- DKIM handle from which to get policy result
**
**  Return value:
**  	DKIM policy check result.
*/

int
dkim_getpresult(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_presult;
}

/*
**  DKIM_GETPRESULTSTR -- retrieve policy result string
**
**  Parameters:
**  	presult -- policy result code to translate
**
**  Return value:
**  	Pointer to text that describes "presult".
*/

const char *
dkim_getpresultstr(int presult)
{
	return dkim_code_to_name(policyresults, presult);
}

/*
**  DKIM_GETPOLICYSTR -- retrieve policy string
**
**  Parameters:
**  	policy -- policy code to translate
**
**  Return value:
**  	Pointer to text that describes "policy".
*/

const char *
dkim_getpolicystr(int policy)
{
	return dkim_code_to_name(policies, policy);
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
*/

DKIM_STAT
dkim_set_dns_callback(DKIM_LIB *libopendkim, void (*func)(const void *context),
                      unsigned int interval)
{
	assert(libopendkim != NULL);

#if USE_ARLIB || USE_UNBOUND
	if (func != NULL && interval == 0)
		return DKIM_STAT_INVALID;

	libopendkim->dkiml_dns_callback = func;
	libopendkim->dkiml_callback_int = interval;

	return DKIM_STAT_OK;
#else /* USE_ARLIB || USE_UNBOUND */
	return DKIM_STAT_INVALID;
#endif /* USE_ARLIB || USE_UNBOUND */
}

#ifdef USE_UNBOUND
/*
**  DKIM_SET_TRUST_ANCHOR -- set path to trust anchor file
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**	tafile -- trust anchor file name
**
**  Return value:
**  	DKIM_STAT_OK -- success
**  	DKIM_STAT_INVALID -- invalid use
*/

DKIM_STAT
dkim_set_trust_anchor(DKIM_LIB *libopendkim, char *tafile)
{
	int status;

	assert(libopendkim != NULL);
	assert(tafile != NULL);

	status = dkim_unbound_add_trustanchor(libopendkim, tafile);

	if (status != 0)
		return DKIM_STAT_INVALID;

	return DKIM_STAT_OK;
}
#endif /* USE_UNBOUND */

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
dkim_set_user_context(DKIM *dkim, const void *ctx)
{
	assert(dkim != NULL);

	dkim->dkim_user_context = ctx;

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

const void *
dkim_get_user_context(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_user_context;
}

#ifdef _FFR_PARSE_TIME
/*
**  DKIM_GET_MSGDATE -- retrieve value extracted from the Date: header
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	time_t representing the value in the Date: header of the message,
**  	or 0 if no such header was found or the value in it was unusable
*/

time_t
dkim_get_msgdate(DKIM *dkim)
{
	assert(dkim != NULL);

	return dkim->dkim_msgdate;
}
#endif /* _FFR_PARSE_TIME */

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
**  DKIM_SET_POLICY_LOOKUP -- set the policy lookup function
**
**  Parameters:
**  	libopendkim -- DKIM library handle
**  	func -- function to call
**
**  Return value:
**  	DKIM_STAT_OK
*/

DKIM_STAT
dkim_set_policy_lookup(DKIM_LIB *libopendkim,
                       int (*func)(DKIM *dkim, u_char *query, _Bool excheck,
                                   u_char *buf, size_t buflen, int *qstat))
{
	assert(libopendkim != NULL);

	libopendkim->dkiml_policy_lookup = func;

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
**  	DKIM_STAT_INVALID -- called against a signing handle or too late
**  	                     (i.e. after dkim_eoh() was called)
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
	return OPENSSL_VERSION_NUMBER;
}

#ifdef QUERY_CACHE
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
	int err;

	assert(lib != NULL);

	if (lib->dkiml_cache == NULL)
		return -1;

	return dkim_cache_expire(lib->dkiml_cache, 0, &err);
}

/*
**  DKIM_GETCACHESTATS -- retrieve cache statistics
**
**  Parameters:
**  	queries -- number of queries handled (returned)
**  	hits -- number of cache hits (returned)
**  	expired -- number of expired hits (returned)
**
**  Return value:
**  	None.
**
**  Notes:
**  	Any of the parameters may be NULL if the corresponding datum
**  	is not of interest.
*/

void
dkim_getcachestats(u_int *queries, u_int *hits, u_int *expired)
{
	dkim_cache_stats(queries, hits, expired);
}
#endif /* QUERY_CACHE */

#ifdef _FFR_DKIM_REPUTATION
/*
**  DKIM_GET_REPUTATION -- query reputation service about a signature
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- DKIM_SIGINFO handle
**  	qroot -- query root
**  	rep -- integer reputation (returned)
**
**  Return value:
**  	DKIM_STAT_OK -- "rep" now contains a reputation
**  	DKIM_STAT_NOKEY -- no reputation data available
**  	DKIM_STAT_CANTVRFY -- data retrieval error of some kind
**  	DKIM_STAT_INTERNAL -- internal error of some kind
*/

DKIM_STAT
dkim_get_reputation(DKIM *dkim, DKIM_SIGINFO *sig, char *qroot, int *rep)
{
	int status;
	int lrep;

	assert(dkim != NULL);
	assert(sig != NULL);
	assert(qroot != NULL);
	assert(rep != NULL);

	status = dkim_reputation(dkim, dkim->dkim_user, dkim->dkim_domain,
	                         dkim_sig_getdomain(sig), qroot, &lrep);

	switch (status)
	{
	  case 1:
		*rep = lrep;
		return DKIM_STAT_OK;

	  case 0:
		return DKIM_STAT_NOKEY;

	  case -1:
		return DKIM_STAT_CANTVRFY;

	  case -2:
	  default:
		return DKIM_STAT_INTERNAL;
	}
}
#endif /* _FFR_DKIM_REPUTATION */
