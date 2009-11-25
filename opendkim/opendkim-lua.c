/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-lua.c,v 1.1.2.16 2009/11/25 07:22:34 cm-msk Exp $
*/

#ifndef lint
static char opendkim_lua_c_id[] = "@(#)$Id: opendkim-lua.c,v 1.1.2.16 2009/11/25 07:22:34 cm-msk Exp $";
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

	/* request a signature (domain, selector) */
	lua_register(l, "odkim_sign", dkimf_xs_requestsig);

	/* retrieve header/value */
	lua_register(l, "odkim_get_header", dkimf_xs_getheader);

	/* pass source IP to dkimf_checkip() */
	lua_register(l, "odkim_internal_ip", dkimf_xs_internalip);

	/* request DB handle */
	lua_register(l, "odkim_get_dbhandle", dkimf_xs_dbhandle);
	lua_pushnumber(l, DB_DOMAINS);
	lua_setglobal(l, "DB_DOMAINS");
	lua_pushnumber(l, DB_THIRDPARTY);
	lua_setglobal(l, "DB_THIRDPARTY");
	lua_pushnumber(l, DB_DONTSIGNTO);
	lua_setglobal(l, "DB_DONTSIGNTO");

	/* get number of envelope recipients */
	lua_register(l, "odkim_rcpt_count", dkimf_xs_rcptcount);

	/* XXX -- TBD
	get a specific envelope recipient
	lua_register(l, "odkim_get_rcpt", dkimf_xs_rcpt);

	test DB for membership
	lua_register(l, "odkim_db_check", dkimf_xs_dbquery);

	get a value from a DB
	lua_register(l, "odkim_db_getvalue", dkimf_xs_dbget);

	request an "l=" tag on a signature
	lua_register(l, "odkim_use_ltag", dkimf_xs_setpartial);
	*/

	lua_pushlightuserdata(l, ctx);
	lua_setglobal(l, "ctx");

	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
	{
	  case 0:
		break;

	  case LUA_ERRSYNTAX:
		if (lua_isstring(l, 1))
			lres->lrs_error = strdup(lua_tostring(l, 1));
		lua_close(l);
		return 1;

	  case LUA_ERRMEM:
		if (lua_isstring(l, 1))
			lres->lrs_error = strdup(lua_tostring(l, 1));
		lua_close(l);
		return -1;

	  default:
		assert(0);
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (lua_isstring(l, 1))
		lres->lrs_error = strdup(lua_tostring(l, 1));

	lua_close(l);

	return (status == 0 ? 0 : 2);
}

/*
**  DKIMF_LUA_VERIFY_HOOK -- hook to LUA for handling a message while signing
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
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
dkimf_lua_verify_hook(void *ctx, const char *script,
                      const char *name, struct dkimf_lua_verify_result *lres)
{
	int status;
	struct dkimf_lua_io io;
	lua_State *l = NULL;

	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	luaL_openlibs(l);

	/*
	**  Register functions.
	*/

	/* XXX
	retrieve number of signatures
	lua_register(l, "odkim_get_sigcount", dkimf_xs_getsigcount);

	retrieve Nth signature
	lua_register(l, "odkim_get_signature", dkimf_xs_getsignature);

	retrieve domain name from signature
	lua_register(l, "odkim_get_sig_getdomain", dkimf_xs_getsigdomain);

	evaluate signature
	lua_register(l, "odkim_get_sig_evaluate", dkimf_xs_evaluate);

	did signature use "l="? / value of l tag
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

	lua_pushlightuserdata(l, ctx);
	lua_setglobal(l, "ctx");

	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
	{
	  case 0:
		break;

	  case LUA_ERRSYNTAX:
		if (lua_isstring(l, 1))
			lres->lrv_error = strdup(lua_tostring(l, 1));
		lua_close(l);
		return 1;

	  case LUA_ERRMEM:
		if (lua_isstring(l, 1))
			lres->lrv_error = strdup(lua_tostring(l, 1));
		lua_close(l);
		return -1;

	  default:
		assert(0);
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (lua_isstring(l, 1))
		lres->lrv_error = strdup(lua_tostring(l, 1));

	lua_close(l);

	return (status == 0 ? 0 : 2);
}

#endif /* _FFR_LUA */
