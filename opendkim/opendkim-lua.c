/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-lua.c,v 1.1.2.6 2009/11/21 04:59:56 cm-msk Exp $
*/

#ifndef lint
static char opendkim_lua_c_id[] = "@(#)$Id: opendkim-lua.c,v 1.1.2.6 2009/11/21 04:59:56 cm-msk Exp $";
#endif /* !lint */

#ifdef _FFR_LUA

/* system includes */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* LUA includes */
#include <lua.h>
#include <lualib.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "opendkim-lua.h"
#include "opendkim-db.h"
#include "opendkim.h"

/* local data types */
struct dkimf_lua_io
{
	_Bool		lua_io_done;
	const char *	lua_io_script;
};

/*
**  DKIMF_LUA_READER -- "read" a script and make it available to LUA
**
**  Parameters:
**  	l -- LUA state
**  	data -- pointer to a LUA I/O structure
**  	size -- size (returned)
**
**  Return value:
**  	Pointer to the data.
*/

static const char *
dkimf_lua_reader(lua_State *l, void *data, size_t *size)
{
	struct dkimf_lua_io *io;

	assert(l != NULL);
	assert(data != NULL);
	assert(size != NULL);

	io = (struct dkimf_lua_io *) data;

	if (io->lua_io_done)
	{
		*size = 0;
		return NULL;
	}
	else
	{
		io->lua_io_done = TRUE;
		*size = strlen(io->lua_io_script);
		return io->lua_io_script;
	}
}

/*
**  DKIMF_LUA_ALLOC -- allocate memory
**
**  Parameters:
**  	ud -- context (not used)
**  	ptr -- pointer (for realloc())
**  	osize --
**  	nsize -- 
**
**  Return value:
**  	Allocated memory, or NULL on failure.
*/

static void *dkimf_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	if (nsize == 0 && osize != 0)
	{
		free(ptr);
		return NULL;
	}
	else if (nsize != 0 && osize == 0)
	{
		return malloc(nsize);
	}
	else
	{
		return realloc(ptr, nsize);
	}
}

/*
**  DKIMF_LUA_SIGN_HOOK -- hook to LUA for handling a message while signing
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	script -- script to run
**  	name -- name of the script (for logging)
**  	lres -- LUA result structure
**
**  Return value:
**  	2 -- processing error
**  	1 -- script contains a syntax error
**  	0 -- success
**  	-1 -- memory allocation failure
**
**  Side effects:
**  	lres may be modified to relay the script's signing requests, i.e.
**  	which key/selector(s) to use, whether to use "l=", etc.
** 
**  Notes:
**  	Called by mlfi_eoh() so it can decide what signature(s) to apply.
**
**  	Will require the ability to access databases, i.e. the
**  	dkimf_db_*() functions and the "conf" handle that contains
**  	references to available databases.  opendkim.c will need to export
**  	some functions for getting DB handles for this purpose.
*/

int
dkimf_lua_sign_hook(void *ctx, const char *script, const char *name,
                    struct dkimf_lua_sign_result *lres)
{
	int c;
	int status;
	lua_State *l = NULL;
	struct dkimf_lua_io io;

	assert(ctx != NULL);
	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	luaL_openlibs(l);

	/*
	**  Register functions
	*/

	/* request From domain */
	lua_register(l, "odkim_get_fromdomain", dkimf_xs_fromdomain);

	/* request source hostname */
	lua_register(l, "odkim_get_clienthost", dkimf_xs_clienthost);

	/* XXX
	request DB handle
	lua_register(l, "odkim_get_dbhandle", dkimf_xs_dbhandle);

	test DB for membership
	lua_register(l, "odkim_db_check", dkimf_xs_dbquery);

	get a value from a DB
	lua_register(l, "odkim_db_getvalue", dkimf_xs_dbget);

	request source IP address
	lua_register(l, "odkim_get_source_ip", dkimf_xs_clientip);

	domain is signable?
	lua_register(l, "odkim_signable_domain", dkimf_xs_signabledomain);

	source is signable?
	lua_register(l, "odkim_signable_ip", dkimf_xs_signableip);

	retrieve header/value
	lua_register(l, "odkim_get_header", dkimf_xs_getheader);
	*/

	/* XXX -- functions to provide to LUA:
	request a signature (domain, selector)
	lua_register(l, "odkim_sign", dkimf_xs_requestsig);

	request an "l=" tag
	lua_register(l, "odkim_bodylength", dkimf_xs_bodylength);

	request a "z=" tag
	lua_register(l, "odkim_diagnostics", dkimf_xs_diagnostics);
	*/

	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
	{
	  case 0:
		break;

	  case LUA_ERRSYNTAX:
		lua_close(l);
		return 1;

	  case LUA_ERRMEM:
		lua_close(l);
		return -1;

	  default:
		assert(0);
	}

	lua_pushlightuserdata(l, ctx);
	lua_setglobal(l, "ctx");

	status = lua_pcall(l, 0, 1, 0);

	lua_close(l);

	return (status == 0 ? 0 : 2);
}

/*
**  DKIMF_LUA_VERIFY_HOOK -- hook to LUA for handling a message while signing
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	dkim -- DKIM verifying handle
**  	script -- script to run
**  	name -- name of the script (for logging)
**  	lres -- LUA result structure
**
**  Return value:
**  	0 -- success
**  	-1 -- failure
**
**  Notes:
**  	Called by mlfi_eom() so it can decide whether or not the message
**  	is acceptable.
**
**  	Will require the ability to access databases, i.e. the
**  	dkimf_db_*() functions and the "conf" handle that contains
**  	references to available databases.  opendkim.c will need to export
**  	some functions for getting DB handles for this purpose.
*/

int
dkimf_lua_verify_hook(void *ctx, DKIM *dkim, const char *script,
                      const char *name, struct dkimf_lua_verify_result *lres)
{
	struct dkimf_lua_io io;
	lua_State *l = NULL;

	assert(ctx != NULL);
	assert(dkim != NULL);
	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	/* register functions */
	/* XXX
	retrieve Nth signature
	lua_register(l, "odkim_get_signature", dkimf_xs_getsignature);

	retrieve domain name from signature
	lua_register(l, "odkim_get_sig_getdomain", dkimf_xs_getsigdomain);

	evaluate signature
	lua_register(l, "odkim_get_sig_evaluate", dkimf_xs_evaluate);

	did signature use "l="?
	lua_register(l, "odkim_check_sig_ltag", dkimf_xs_getltag);

	size of body?
	lua_register(l, "odkim_get_bodylength", dkimf_xs_bodylength);

	canonicalizations?
	lua_register(l, "odkim_get_bodycanon", dkimf_xs_bodycanon);
	lua_register(l, "odkim_get_hdrcanon", dkimf_xs_hdrcanon);

	get policy result
	lua_register(l, "odkim_get_policy", dkimf_xs_getpolicy);

	set result code
	lua_register(l, "odkim_set_result_code", dkimf_xs_setresult);

	set reply text
	lua_register(l, "odkim_set_reply_text", dkimf_xs_setreplytext);

	quarantine?
	lua_register(l, "odkim_quarantine", dkimf_xs_quarantine);

	redirect
	lua_register(l, "odkim_redirect", dkimf_xs_redirect);
	*/

	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
	{
	  case 0:
		break;

	  case LUA_ERRSYNTAX:
		lua_close(l);
		return 1;

	  case LUA_ERRMEM:
		lua_close(l);
		return -1;

	  default:
		assert(0);
	}

	lua_close(l);

	return 0;
}

#endif /* _FFR_LUA */
