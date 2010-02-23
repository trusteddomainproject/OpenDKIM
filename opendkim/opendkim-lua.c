/*
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-lua.c,v 1.12 2010/02/23 22:37:36 cm-msk Exp $
*/

#ifndef lint
static char opendkim_lua_c_id[] = "@(#)$Id: opendkim-lua.c,v 1.12 2010/02/23 22:37:36 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

#ifdef USE_LUA

/* system includes */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* Lua includes */
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#define DKIMF_LUA_PROTOTYPES
#include "opendkim-lua.h"
#include "opendkim-db.h"
#include "opendkim.h"

/* local data types */
struct dkimf_lua_io
{
	_Bool		lua_io_done;
	const char *	lua_io_script;
};

/* libraries */
static const luaL_Reg dkimf_lua_lib_setup[] =
{
	{ "check_popauth",	dkimf_xs_popauth	},
	{ "db_check",		dkimf_xs_dbquery	},
	{ "get_clienthost",	dkimf_xs_clienthost	},
	{ "get_clientip",	dkimf_xs_clientip	},
	{ "get_dbhandle",	dkimf_xs_dbhandle	},
	{ "get_fromdomain",	dkimf_xs_fromdomain	},
	{ "get_header",		dkimf_xs_getheader	},
	{ "get_mtasymbol",	dkimf_xs_getsymval	},
	{ "get_rcpt",		dkimf_xs_rcpt		},
	{ "get_rcptarray",	dkimf_xs_rcptarray	},
	{ "internal_ip",	dkimf_xs_internalip	},
	{ "log",		dkimf_xs_log		},
	{ "rcpt_count",		dkimf_xs_rcptcount	},
	{ "resign",		dkimf_xs_resign		},
	{ "set_result",		dkimf_xs_setresult	},
	{ "sign",		dkimf_xs_requestsig	},
	{ "use_ltag",		dkimf_xs_setpartial	},
	{ "verify",		dkimf_xs_verify		},
	{ NULL,			NULL			}
};

static const luaL_Reg dkimf_lua_lib_screen[] =
{
	{ "db_check",		dkimf_xs_dbquery	},
	{ "get_dbhandle",	dkimf_xs_dbhandle	},
	{ "get_fromdomain",	dkimf_xs_fromdomain	},
	{ "get_header",		dkimf_xs_getheader	},
	{ "get_rcpt",		dkimf_xs_rcpt		},
	{ "get_rcptarray",	dkimf_xs_rcptarray	},
	{ "get_sigarray",	dkimf_xs_getsigarray	},
	{ "get_sigcount",	dkimf_xs_getsigcount	},
	{ "get_sighandle",	dkimf_xs_getsighandle	},
	{ "log",		dkimf_xs_log		},
	{ "rcpt_count",		dkimf_xs_rcptcount	},
	{ "sig_getdomain",	dkimf_xs_getsigdomain	},
	{ "sig_getidentity",	dkimf_xs_getsigidentity	},
	{ "sig_ignore",		dkimf_xs_sigignore	},
	{ NULL,			NULL			}
};

static const luaL_Reg dkimf_lua_lib_final[] =
{
	{ "add_rcpt",		dkimf_xs_addrcpt	},
	{ "del_rcpt",		dkimf_xs_delrcpt	},
	{ "get_policy",		dkimf_xs_getpolicy	},
	{ "get_rcpt",		dkimf_xs_rcpt		},
	{ "get_rcptarray",	dkimf_xs_rcptarray	},
	{ "get_reputation",	dkimf_xs_getreputation	},
	{ "get_sigarray",	dkimf_xs_getsigarray	},
	{ "get_sigcount",	dkimf_xs_getsigcount	},
	{ "get_sighandle",	dkimf_xs_getsighandle	},
	{ "log",		dkimf_xs_log		},
	{ "quarantine",		dkimf_xs_quarantine	},
	{ "rcpt_count",		dkimf_xs_rcptcount	},
	{ "set_result",		dkimf_xs_setresult	},
	{ "set_smtp_reply",	dkimf_xs_setreply	},
	{ "sig_bhresult",	dkimf_xs_sigbhresult	},
	{ "sig_bodylength",	dkimf_xs_bodylength	},
	{ "sig_canonlength",	dkimf_xs_canonlength	},
	{ "sig_getdomain",	dkimf_xs_getsigdomain	},
	{ "sig_getidentity",	dkimf_xs_getsigidentity	},
	{ "sig_result",		dkimf_xs_sigresult	},
	{ NULL,			NULL			}
};

/*
**  DKIMF_LUA_READER -- "read" a script and make it available to Lua
**
**  Parameters:
**  	l -- Lua state
**  	data -- pointer to a Lua I/O structure
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
**  	osize -- old size
**  	nsize --  new size
**
**  Return value:
**  	Allocated memory, or NULL on failure.
*/

static void *
dkimf_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
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
**  DKIMF_LUA_SETUP_HOOK -- hook to Lua for handling a message during setup
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	script -- script to run
**  	name -- name of the script (for logging)
**  	lres -- Lua result structure
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
	*/

	luaL_register(l, "odkim", dkimf_lua_lib_setup);
	lua_pop(l, 1);

	/*
	**  Register constants.
	*/

	/* DB handle constants */
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

	/* set result code */
	lua_pushnumber(l, SMFIS_TEMPFAIL);
	lua_setglobal(l, "SMFIS_TEMPFAIL");
	lua_pushnumber(l, SMFIS_ACCEPT);
	lua_setglobal(l, "SMFIS_ACCEPT");
	lua_pushnumber(l, SMFIS_DISCARD);
	lua_setglobal(l, "SMFIS_DISCARD");
	lua_pushnumber(l, SMFIS_REJECT);
	lua_setglobal(l, "SMFIS_REJECT");

	/* filter context */
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
**  DKIMF_LUA_SCREEN_HOOK -- hook to Lua for handling a message after the
**                           verifying handle is established and all headers
**                           have been fed to it
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	script -- script to run
**  	name -- name of the script (for logging)
**  	lres -- Lua result structure
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
	*/

	luaL_register(l, "odkim", dkimf_lua_lib_screen);
	lua_pop(l, 1);

	/*
	**  Register constants.
	*/

	/* DB handles */
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

	/* milter context */
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
**  DKIMF_LUA_FINAL_HOOK -- hook to Lua for handling a message after all
**                          signing and verifying has been done
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	script -- script to run
**  	name -- name of the script (for logging)
**  	lres -- Lua result structure
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
	*/

	luaL_register(l, "odkim", dkimf_lua_lib_final);
	lua_pop(l, 1);

	/*
	**  Register constants.
	*/

	/* policy codes */
	lua_pushnumber(l, DKIMF_POLICY_UNKNOWN);
	lua_setglobal(l, "DKIMF_POLICY_UNKNOWN");
	lua_pushnumber(l, DKIMF_POLICY_ALL);
	lua_setglobal(l, "DKIMF_POLICY_ALL");
	lua_pushnumber(l, DKIMF_POLICY_DISCARDABLE);
	lua_setglobal(l, "DKIMF_POLICY_DISCARDABLE");
	lua_pushnumber(l, DKIMF_POLICY_NONE);
	lua_setglobal(l, "DKIMF_POLICY_NONE");
	lua_pushnumber(l, DKIMF_POLICY_NXDOMAIN);
	lua_setglobal(l, "DKIMF_POLICY_NXDOMAIN");

	/* result codes */
	lua_pushnumber(l, SMFIS_TEMPFAIL);
	lua_setglobal(l, "SMFIS_TEMPFAIL");
	lua_pushnumber(l, SMFIS_ACCEPT);
	lua_setglobal(l, "SMFIS_ACCEPT");
	lua_pushnumber(l, SMFIS_DISCARD);
	lua_setglobal(l, "SMFIS_DISCARD");
	lua_pushnumber(l, SMFIS_REJECT);
	lua_setglobal(l, "SMFIS_REJECT");

	/* milter context */
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
#endif /* USE_LUA */
