/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-lua.c,v 1.1.2.39 2009/11/28 06:59:30 cm-msk Exp $
*/

#ifndef lint
static char opendkim_lua_c_id[] = "@(#)$Id: opendkim-lua.c,v 1.1.2.39 2009/11/28 06:59:30 cm-msk Exp $";
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
**  DKIMF_LUA_SETUP_HOOK -- hook to LUA for handling a message during setup
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
dkimf_lua_setup_hook(void *ctx, const char *script, const char *name,
                     struct dkimf_lua_script_result *lres)
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
	**  Register functions.
	**
	**  XXX -- turn this into a LUA library?
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

	/* do POPAUTH check */
	lua_register(l, "odkim_check_popauth", dkimf_xs_popauth);

	/* request DB handle */
	/* XXX -- allow creation of arbitrary DB handles? */
	lua_register(l, "odkim_get_dbhandle", dkimf_xs_dbhandle);
	lua_pushnumber(l, DB_DOMAINS);
	lua_setglobal(l, "DB_DOMAINS");
	lua_pushnumber(l, DB_THIRDPARTY);
	lua_setglobal(l, "DB_THIRDPARTY");
	lua_pushnumber(l, DB_DONTSIGNTO);
	lua_setglobal(l, "DB_DONTSIGNTO");
	lua_pushnumber(l, DB_MTAS);
	lua_setglobal(l, "DB_MTAS");
	lua_pushnumber(l, DB_MACROS);
	lua_setglobal(l, "DB_MACROS");

	/* get number of envelope recipients */
	lua_register(l, "odkim_rcpt_count", dkimf_xs_rcptcount);

	/* get a specific envelope recipient */
	lua_register(l, "odkim_get_rcpt", dkimf_xs_rcpt);

	/* test DB for membership */
	lua_register(l, "odkim_db_check", dkimf_xs_dbquery);

	/* request an "l=" tag on new signatures */
	lua_register(l, "odkim_use_ltag", dkimf_xs_setpartial);

	/* request that the message be sent through verification */
	lua_register(l, "odkim_verify", dkimf_xs_verify);

	/* retrieve an MTA symbol */
	lua_register(l, "odkim_get_mtasymbol", dkimf_xs_getsymval);

	/* set up for re-signing */
	lua_register(l, "odkim_resign", dkimf_xs_resign);

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
**  DKIMF_LUA_SCREEN_HOOK -- hook to LUA for handling a message after the
**                           verifying handle is established and all headers
**                           have been fed to it
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
dkimf_lua_screen_hook(void *ctx, const char *script,
                      const char *name, struct dkimf_lua_script_result *lres)
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
	**
	**  XXX -- turn this into a LUA library?
	*/

	/* test DB for membership */
	lua_register(l, "odkim_db_check", dkimf_xs_dbquery);

	/* request From domain */
	lua_register(l, "odkim_get_fromdomain", dkimf_xs_fromdomain);

	/* request DB handle */
	/* XXX -- allow creation of arbitrary DB handles? */
	lua_register(l, "odkim_get_dbhandle", dkimf_xs_dbhandle);
	lua_pushnumber(l, DB_DOMAINS);
	lua_setglobal(l, "DB_DOMAINS");
	lua_pushnumber(l, DB_THIRDPARTY);
	lua_setglobal(l, "DB_THIRDPARTY");
	lua_pushnumber(l, DB_DONTSIGNTO);
	lua_setglobal(l, "DB_DONTSIGNTO");
	lua_pushnumber(l, DB_MTAS);
	lua_setglobal(l, "DB_MTAS");
	lua_pushnumber(l, DB_MACROS);
	lua_setglobal(l, "DB_MACROS");

	/* retrieve header/value */
	lua_register(l, "odkim_get_header", dkimf_xs_getheader);

	/* get a specific envelope recipient */
	lua_register(l, "odkim_get_rcpt", dkimf_xs_rcpt);

	/* get number of envelope recipients */
	lua_register(l, "odkim_rcpt_count", dkimf_xs_rcptcount);

	/* retrieve number of signatures */
	lua_register(l, "odkim_get_sigcount", dkimf_xs_getsigcount);

	/* retrieve a signature handle */
	lua_register(l, "odkim_get_sighandle", dkimf_xs_getsighandle);

	/* retrieve a signature's domain */
	lua_register(l, "odkim_sig_getdomain", dkimf_xs_getsigdomain);

	/* retrieve a signature's identity */
	lua_register(l, "odkim_sig_getidentity", dkimf_xs_getsigidentity);

	/* ignore a signature and its result */
	lua_register(l, "odkim_sig_ignore", dkimf_xs_sigignore);

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
**  DKIMF_LUA_FINAL_HOOK -- hook to LUA for handling a message after all
**                          signing and verifying has been done
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
dkimf_lua_final_hook(void *ctx, const char *script,
                     const char *name, struct dkimf_lua_script_result *lres)
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
	**
	**  XXX -- turn this into a LUA library?
	*/

	/* retrieve number of signatures */
	lua_register(l, "odkim_get_sigcount", dkimf_xs_getsigcount);

	/* retrieve a signature handle */
	lua_register(l, "odkim_get_sighandle", dkimf_xs_getsighandle);

	/* retrieve a signature's domain */
	lua_register(l, "odkim_sig_getdomain", dkimf_xs_getsigdomain);

	/* retrieve a signature's identity */
	lua_register(l, "odkim_sig_getidentity", dkimf_xs_getsigidentity);

	/* retrieve signature result */
	lua_register(l, "odkim_sig_result", dkimf_xs_sigresult);

	/* retrieve signature result (body hash check) */
	lua_register(l, "odkim_sig_bhresult", dkimf_xs_sigbhresult);

	/* size of body? */
	lua_register(l, "odkim_sig_bodylength", dkimf_xs_bodylength);

	/* canonicalized size? */
	lua_register(l, "odkim_sig_canonlength", dkimf_xs_canonlength);

	/* get a specific envelope recipient */
	lua_register(l, "odkim_get_rcpt", dkimf_xs_rcpt);

	/* get number of envelope recipients */
	lua_register(l, "odkim_rcpt_count", dkimf_xs_rcptcount);

	/* add recipient */
	lua_register(l, "odkim_add_rcpt", dkimf_xs_addrcpt);

	/* delete recipient */
	lua_register(l, "odkim_delete_rcpt", dkimf_xs_delrcpt);

	/* get policy code */
	lua_pushnumber(l, DKIM_POLICY_UNKNOWN);
	lua_setglobal(l, "DKIM_POLICY_UNKNOWN");
	lua_pushnumber(l, DKIM_POLICY_ALL);
	lua_setglobal(l, "DKIM_POLICY_ALL");
	lua_pushnumber(l, DKIM_POLICY_DISCARDABLE);
	lua_setglobal(l, "DKIM_POLICY_DISCARDABLE");
	lua_register(l, "odkim_get_policy", dkimf_xs_getpolicy);

	/* get reputation */
	lua_register(l, "odkim_get_reputation", dkimf_xs_getreputation);

	/* get policy result */
	lua_pushnumber(l, DKIM_PRESULT_NONE);
	lua_setglobal(l, "DKIM_PRESULT_NONE");
	lua_pushnumber(l, DKIM_PRESULT_NXDOMAIN);
	lua_setglobal(l, "DKIM_PRESULT_NXDOMAIN");
	lua_pushnumber(l, DKIM_PRESULT_AUTHOR);
	lua_setglobal(l, "DKIM_PRESULT_AUTHOR");
	lua_register(l, "odkim_get_presult", dkimf_xs_getpresult);

	/* set SMTP reply */
	lua_register(l, "odkim_set_smtp_reply", dkimf_xs_setreply);

	/* quarantine */
	lua_register(l, "odkim_quarantine", dkimf_xs_quarantine);

	/* set result code */
	lua_pushnumber(l, SMFIS_TEMPFAIL);
	lua_setglobal(l, "SMFIS_TEMPFAIL");
	lua_pushnumber(l, SMFIS_DISCARD);
	lua_setglobal(l, "SMFIS_DISCARD");
	lua_pushnumber(l, SMFIS_REJECT);
	lua_setglobal(l, "SMFIS_REJECT");
	lua_register(l, "odkim_set_result", dkimf_xs_setresult);

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
#endif /* _FFR_LUA */
