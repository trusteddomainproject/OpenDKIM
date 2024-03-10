/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, 2014, 2015, 2018, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* libopendkim includes */
#include "dkim-internal.h"

/* structures */
struct dkim_nametable
{
	const char *	tbl_name;	/* name */
	const int	tbl_code;	/* code */
};

struct dkim_iter_ctx
{
	DKIM_NAMETABLE	*current;	/* current table entry */
	_Bool		is_eot;		/* It is last entry or not */
};

/* lookup tables */
static struct dkim_nametable prv_keyparams[] =	/* key parameters */
{
	{ "a",		DKIM_KEY_ALGORITHM },
	{ "n",		DKIM_KEY_NOTES },
	{ "p",		DKIM_KEY_DATA },
	{ "s",		DKIM_KEY_SERVICE },
	{ "t",		DKIM_KEY_FLAGS },
	{ "v",		DKIM_KEY_VERSION },
	{ NULL,		-1 }
};
DKIM_NAMETABLE *dkim_table_keyparams = prv_keyparams;

static struct dkim_nametable prv_keyflags[] =	/* key flags */
{
	{ "y",		DKIM_SIGFLAG_TESTKEY },
	{ "s",		DKIM_SIGFLAG_NOSUBDOMAIN },
	{ NULL,		-1 }
};
DKIM_NAMETABLE *dkim_table_keyflags = prv_keyflags;

static struct dkim_nametable prv_sigparams[] =	/* signature parameters */
{
	{ "a",		DKIM_PARAM_SIGNALG },
	{ "b",		DKIM_PARAM_SIGNATURE },
	{ "bh",		DKIM_PARAM_BODYHASH },
	{ "c",		DKIM_PARAM_CANONALG },
	{ "d",		DKIM_PARAM_DOMAIN },
	{ "h",		DKIM_PARAM_HDRLIST },
	{ "i",		DKIM_PARAM_IDENTITY },
	{ "l",		DKIM_PARAM_BODYLENGTH },
	{ "q",		DKIM_PARAM_QUERYMETHOD },
	{ "s",		DKIM_PARAM_SELECTOR },
	{ "t",		DKIM_PARAM_TIMESTAMP },
	{ "v",		DKIM_PARAM_VERSION },
	{ "x",		DKIM_PARAM_EXPIRATION },
	{ "z",		DKIM_PARAM_COPIEDHDRS },
	{ NULL,		-1 }
};
DKIM_NAMETABLE *dkim_table_sigparams = prv_sigparams;

static struct dkim_nametable prv_algorithms[] =	/* signing algorithms */
{
	{ "rsa-sha1",		DKIM_SIGN_RSASHA1 },
	{ "rsa-sha256",		DKIM_SIGN_RSASHA256 },
	{ "ed25519-sha256",	DKIM_SIGN_ED25519SHA256 },
	{ NULL,		-1 },
};
DKIM_NAMETABLE *dkim_table_algorithms = prv_algorithms;

static struct dkim_nametable prv_canonicalizations[] = /* canonicalizations */
{
	{ "simple",	DKIM_CANON_SIMPLE },
	{ "relaxed",	DKIM_CANON_RELAXED },
	{ NULL,		-1 },
};
DKIM_NAMETABLE *dkim_table_canonicalizations = prv_canonicalizations;

static struct dkim_nametable prv_hashes[] =		/* hashes */
{
	{ "sha1",	DKIM_HASHTYPE_SHA1 },
	{ "sha256",	DKIM_HASHTYPE_SHA256 },
	{ NULL,		-1 },
};
DKIM_NAMETABLE *dkim_table_hashes = prv_hashes;

static struct dkim_nametable prv_keytypes[] =	/* key types */
{
	{ "rsa",	DKIM_KEYTYPE_RSA },
	{ "ed25519",	DKIM_KEYTYPE_ED25519 },
	{ NULL,		-1 },
};
DKIM_NAMETABLE *dkim_table_keytypes = prv_keytypes;

static struct dkim_nametable prv_querytypes[] =	/* query types */
{
	{ "dns",	DKIM_QUERY_DNS },
	{ NULL,		-1 },
};
DKIM_NAMETABLE *dkim_table_querytypes = prv_querytypes;

static struct dkim_nametable prv_results[] =		/* result codes */
{
	{ "Success",			DKIM_STAT_OK },
	{ "Bad signature",		DKIM_STAT_BADSIG },
	{ "No signature",		DKIM_STAT_NOSIG },
	{ "No key",			DKIM_STAT_NOKEY },
	{ "Unable to verify",		DKIM_STAT_CANTVRFY },
	{ "Syntax error",		DKIM_STAT_SYNTAX },
	{ "Resource unavailable",	DKIM_STAT_NORESOURCE },
	{ "Internal error",		DKIM_STAT_INTERNAL },
	{ "Revoked key",		DKIM_STAT_REVOKED },
	{ "Invalid parameter",		DKIM_STAT_INVALID },
	{ "Not implemented",		DKIM_STAT_NOTIMPLEMENT },
	{ "Key retrieval failed",	DKIM_STAT_KEYFAIL },
	{ "Reject requested",		DKIM_STAT_CBREJECT },
	{ "Invalid result",		DKIM_STAT_CBINVALID },
	{ "Try again later",		DKIM_STAT_CBTRYAGAIN },
	{ "Multiple DNS replies",	DKIM_STAT_MULTIDNSREPLY },
	{ "End of the table",		DKIM_STAT_ITER_EOT },
	{ NULL,				-1 },
};
DKIM_NAMETABLE *dkim_table_results = prv_results;

static struct dkim_nametable prv_settypes[] =	/* set types */
{
	{ "key",			DKIM_SETTYPE_KEY },
	{ "signature",			DKIM_SETTYPE_SIGNATURE },
	{ "signature reporting", 	DKIM_SETTYPE_SIGREPORT },
	{ NULL,		-1 },
};
DKIM_NAMETABLE *dkim_table_settypes = prv_settypes;

static struct dkim_nametable prv_sigerrors[] =	/* signature parsing errors */
{
	{ "no signature error", 		DKIM_SIGERROR_OK },
	{ "unsupported signature version",	DKIM_SIGERROR_VERSION },
	{ "invalid domain coverage",		DKIM_SIGERROR_DOMAIN },
	{ "signature expired",			DKIM_SIGERROR_EXPIRED },
	{ "signature timestamp in the future",	DKIM_SIGERROR_FUTURE },
	{ "signature timestamp order error",	DKIM_SIGERROR_TIMESTAMPS },
	{ "invalid header canonicalization",	DKIM_SIGERROR_INVALID_HC },
	{ "invalid body canonicalization",	DKIM_SIGERROR_INVALID_BC },
	{ "signature algorithm missing",	DKIM_SIGERROR_MISSING_A },
	{ "signature algorithm invalid",	DKIM_SIGERROR_INVALID_A },
	{ "header list missing",		DKIM_SIGERROR_MISSING_H },
	{ "body length value invalid",		DKIM_SIGERROR_INVALID_L },
	{ "query method invalid",		DKIM_SIGERROR_INVALID_Q },
	{ "query option invalid",		DKIM_SIGERROR_INVALID_QO },
	{ "domain tag missing",			DKIM_SIGERROR_MISSING_D },
	{ "domain tag empty",			DKIM_SIGERROR_EMPTY_D },
	{ "selector tag missing",		DKIM_SIGERROR_MISSING_S },
	{ "selector tag empty",			DKIM_SIGERROR_EMPTY_S },
	{ "signature data missing",		DKIM_SIGERROR_MISSING_B },
	{ "signature data empty",		DKIM_SIGERROR_EMPTY_B },
	{ "signature data corrupt",		DKIM_SIGERROR_CORRUPT_B },
	{ "key not found in DNS",		DKIM_SIGERROR_NOKEY },
	{ "key DNS reply corrupt",		DKIM_SIGERROR_DNSSYNTAX },
	{ "key DNS query failed",		DKIM_SIGERROR_KEYFAIL },
	{ "body hash missing",			DKIM_SIGERROR_MISSING_BH },
	{ "body hash empty",			DKIM_SIGERROR_EMPTY_BH },
	{ "body hash corrupt",			DKIM_SIGERROR_CORRUPT_BH },
	{ "signature verification failed",	DKIM_SIGERROR_BADSIG },
	{ "unauthorized subdomain",		DKIM_SIGERROR_SUBDOMAIN },
	{ "multiple keys found",		DKIM_SIGERROR_MULTIREPLY },
	{ "header list tag empty",		DKIM_SIGERROR_EMPTY_H },
	{ "header list missing required entries", DKIM_SIGERROR_INVALID_H },
	{ "length tag value exceeds body size", DKIM_SIGERROR_TOOLARGE_L },
	{ "unprotected header field",		DKIM_SIGERROR_MBSFAILED },
	{ "unknown key version",		DKIM_SIGERROR_KEYVERSION },
	{ "unknown key hash",			DKIM_SIGERROR_KEYUNKNOWNHASH },
	{ "signature-key hash mismatch",	DKIM_SIGERROR_KEYHASHMISMATCH },
	{ "not an e-mail key",			DKIM_SIGERROR_NOTEMAILKEY },
	{ "key type missing",			DKIM_SIGERROR_KEYTYPEMISSING },
	{ "unknown key type",			DKIM_SIGERROR_KEYTYPEUNKNOWN },
	{ "key revoked",			DKIM_SIGERROR_KEYREVOKED },
	{ "unable to apply public key",		DKIM_SIGERROR_KEYDECODE },
	{ "version missing",			DKIM_SIGERROR_MISSING_V },
	{ "version empty",			DKIM_SIGERROR_EMPTY_V },
	{ "signing key too small",		DKIM_SIGERROR_KEYTOOSMALL },
#ifdef _FFR_CONDITIONAL
	{ "conditional signature not satisfied", DKIM_SIGERROR_CONDITIONAL },
	{ "too many signature indirections",	DKIM_SIGERROR_CONDLOOP },
#endif /* _FFR_CONDITIONAL */
	{ NULL,					-1 },
};
DKIM_NAMETABLE *dkim_table_sigerrors = prv_sigerrors;

#ifdef _FFR_CONDITIONAL
static struct dkim_nametable prv_mandatory[] =	/* mandatory DKIM tags */
{
	{ "!cd",	0 },
	{ NULL,		-1 },
};
DKIM_NAMETABLE *dkim_table_mandatory = prv_mandatory;
#endif /* _FFR_CONDITIONAL */

/* ===================================================================== */

/*
**  DKIM_CODE_TO_NAME -- translate a mnemonic code to its name
**
**  Parameters:
**  	tbl -- name table
**  	code -- code to translate
**
**  Return value:
**  	Pointer to the name matching the provided code, or NULL if not found.
*/

const char *
dkim_code_to_name(DKIM_NAMETABLE *tbl, const int code)
{
	int c;

	assert(tbl != NULL);

	for (c = 0; ; c++)
	{
		if (tbl[c].tbl_code == -1 && tbl[c].tbl_name == NULL)
			return NULL;

		if (tbl[c].tbl_code == code)
			return tbl[c].tbl_name;
	}
}

/*
**  DKIM_NAME_TO_CODE -- translate a name to a mnemonic code
**
**  Parameters:
**  	tbl -- name table
**  	name -- name to translate
**
**  Return value:
**  	A mnemonic code matching the provided name, or -1 if not found.
*/

const int
dkim_name_to_code(DKIM_NAMETABLE *tbl, const char *name)
{
	int c;

	assert(tbl != NULL);

	for (c = 0; ; c++)
	{
		if (tbl[c].tbl_code == -1 && tbl[c].tbl_name == NULL)
			return -1;

		if (strcasecmp(tbl[c].tbl_name, name) == 0)
			return tbl[c].tbl_code;
	}
}

/*
**  DKIM_NAMETABLE_FIRST -- get the first entry of the table and start iteration
**
**  Parameters:
**  	tbl -- name table
**  	ctx -- iteration context (returned)
**  	name -- name in the first item in the table (returned)
**  	code -- code in the first item in the table (returned)
**
**  Return value:
**  	A DKIM_STAT_OK         -- retrieve the first item successfully
**  	A DKIM_STAT_ITER_EOT   -- the table has no item.
**  	A DKIM_STAT_NORESOURCE -- cannot allocate memory for the
** 	                          iteration context
**
*/
DKIM_STAT
dkim_nametable_first(DKIM_NAMETABLE *tbl, DKIM_ITER_CTX **ctx,
                 const char **name, int *code)
{
	*ctx = (DKIM_ITER_CTX *)
	       malloc(sizeof(DKIM_ITER_CTX));
	if (*ctx == NULL)
	{
		return DKIM_STAT_NORESOURCE;
	}
	if (tbl->tbl_name == NULL)
	{
		(*ctx)->current = NULL;
		(*ctx)->is_eot = TRUE;
		return DKIM_STAT_ITER_EOT;
	}
	*name = tbl->tbl_name;
	*code = tbl->tbl_code;
	(*ctx)->current = tbl;
	(*ctx)->is_eot = (((*ctx)->current)[1].tbl_name == NULL)? TRUE : FALSE;
	return DKIM_STAT_OK;
}

/*
**  DKIM_NAMETABLE_NEXT -- get the next entry on the iteration the table
**
**  Parameters:
**  	ctx -- iteration context (updated)
**  	name -- name in the first item in the table (returned)
**  	code -- code in the first item in the table (returned)
**
**  Return value:
**  	A DKIM_STAT_OK         -- retrieve the first item successfully
**  	A DKIM_STAT_ITER_EOT   -- the table has no item.
**
*/
DKIM_STAT
dkim_nametable_next(DKIM_ITER_CTX *ctx, const char **name, int *code)
{
	if (ctx->is_eot)
	{
		return DKIM_STAT_ITER_EOT;
	}
	ctx->current++;
	*name = ctx->current->tbl_name;
	*code = ctx->current->tbl_code;
	ctx->is_eot = ((ctx->current)[1].tbl_name == NULL)? TRUE : FALSE;
	return DKIM_STAT_OK;
}

/*
**  DKIM_ITER_CTX_FREE -- release resources associated with
**                                  a nametable iteration context
**
**  Parameters:
**  	ctx -- iteration context
**
**  Return value:
**  	DKIM_STAT_OK  -- operation was successful
**
**  Note: This function is a placeholder to add some operation associated
**        with future changes of the structure of the tables.
**
*/
DKIM_STAT
dkim_iter_ctx_free(DKIM_ITER_CTX *ctx)
{
	if (ctx != NULL)
	{
		free((void *)ctx);
	}
	return DKIM_STAT_OK;
}
