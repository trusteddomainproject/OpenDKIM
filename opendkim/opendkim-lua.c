/*
**  Copyright (c) 2009-2015, The Trusted Domain Project.  All rights reserved.
*/

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
#define DKIMF_MILTER_PROTOTYPES
#include "opendkim-lua.h"
#include "opendkim-db.h"
#include "opendkim.h"

/* local data types */
struct dkimf_lua_io
{
	_Bool		lua_io_done;
	const char *	lua_io_script;
	size_t		lua_io_len;
	size_t		lua_io_alloc;
};

#ifdef DKIMF_LUA_CONTEXT_HOOKS
/* libraries */
static const luaL_Reg dkimf_lua_lib_setup[] =
{
	{ "check_popauth",	dkimf_xs_popauth	},
	{ "db_check",		dkimf_xs_dbquery	},
	{ "db_close",		dkimf_xs_dbclose	},
	{ "db_open",		dkimf_xs_dbopen		},
	{ "export",		dkimf_xs_export		},
	{ "get_clienthost",	dkimf_xs_clienthost	},
	{ "get_clientip",	dkimf_xs_clientip	},
	{ "get_dbhandle",	dkimf_xs_dbhandle	},
	{ "get_envfrom",	dkimf_xs_getenvfrom	},
	{ "get_fromdomain",	dkimf_xs_fromdomain	},
	{ "get_header",		dkimf_xs_getheader	},
	{ "get_mtasymbol",	dkimf_xs_getsymval	},
	{ "get_rcpt",		dkimf_xs_rcpt		},
	{ "get_rcptarray",	dkimf_xs_rcptarray	},
	{ "internal_ip",	dkimf_xs_internalip	},
	{ "log",		dkimf_xs_log		},
	{ "rcpt_count",		dkimf_xs_rcptcount	},
	{ "replace_header",	dkimf_xs_replaceheader	},
	{ "resign",		dkimf_xs_resign		},
	{ "set_result",		dkimf_xs_setresult	},
	{ "sign",		dkimf_xs_requestsig	},
	{ "signfor",		dkimf_xs_signfor	},
#ifdef _FFR_REPUTATION
	{ "spam",		dkimf_xs_spam		},
#endif /* _FFR_REPUTATION */
	{ "use_ltag",		dkimf_xs_setpartial	},
	{ "verify",		dkimf_xs_verify		},
	{ "xtag",		dkimf_xs_xtag		},
	{ NULL,			NULL			}
};

static const luaL_Reg dkimf_lua_lib_screen[] =
{
	{ "db_check",		dkimf_xs_dbquery	},
	{ "db_close",		dkimf_xs_dbclose	},
	{ "db_open",		dkimf_xs_dbopen		},
	{ "export",		dkimf_xs_export		},
	{ "get_dbhandle",	dkimf_xs_dbhandle	},
	{ "get_envfrom",	dkimf_xs_getenvfrom	},
	{ "get_fromdomain",	dkimf_xs_fromdomain	},
	{ "get_header",		dkimf_xs_getheader	},
	{ "get_mtasymbol",	dkimf_xs_getsymval	},
	{ "get_rcpt",		dkimf_xs_rcpt		},
	{ "get_rcptarray",	dkimf_xs_rcptarray	},
	{ "get_sigarray",	dkimf_xs_getsigarray	},
	{ "get_sigcount",	dkimf_xs_getsigcount	},
	{ "get_sighandle",	dkimf_xs_getsighandle	},
	{ "internal_ip",	dkimf_xs_internalip	},
	{ "log",		dkimf_xs_log		},
	{ "parse_field",	dkimf_xs_parsefield	},
	{ "rcpt_count",		dkimf_xs_rcptcount	},
	{ "sig_getdomain",	dkimf_xs_getsigdomain	},
	{ "sig_getidentity",	dkimf_xs_getsigidentity	},
	{ "sig_ignore",		dkimf_xs_sigignore	},
#ifdef _FFR_REPUTATION
	{ "spam",		dkimf_xs_spam		},
#endif /* _FFR_REPUTATION */
	{ NULL,			NULL			}
};

# ifdef _FFR_STATSEXT
static const luaL_Reg dkimf_lua_lib_stats[] =
{
	{ "export",		dkimf_xs_export		},
	{ "get_envfrom",	dkimf_xs_getenvfrom	},
	{ "get_header",		dkimf_xs_getheader	},
	{ "get_mtasymbol",	dkimf_xs_getsymval	},
	{ "get_rcpt",		dkimf_xs_rcpt		},
	{ "get_rcptarray",	dkimf_xs_rcptarray	},
	{ "get_sigarray",	dkimf_xs_getsigarray	},
	{ "get_sigcount",	dkimf_xs_getsigcount	},
	{ "get_sighandle",	dkimf_xs_getsighandle	},
	{ "internal_ip",	dkimf_xs_internalip	},
	{ "log",		dkimf_xs_log		},
	{ "parse_field",	dkimf_xs_parsefield	},
#  ifdef _FFR_RBL
	{ "rbl_check",		dkimf_xs_rblcheck	},
#  endif /* _FFR_RBL */
	{ "rcpt_count",		dkimf_xs_rcptcount	},
	{ "sig_bhresult",	dkimf_xs_sigbhresult	},
	{ "sig_bodylength",	dkimf_xs_bodylength	},
	{ "sig_canonlength",	dkimf_xs_canonlength	},
	{ "sig_getdomain",	dkimf_xs_getsigdomain	},
	{ "sig_getidentity",	dkimf_xs_getsigidentity	},
	{ "sig_result",		dkimf_xs_sigresult	},
	{ "stats",		dkimf_xs_statsext	},
#ifdef _FFR_REPUTATION
	{ "spam",		dkimf_xs_spam		},
#endif /* _FFR_REPUTATION */
	{ NULL,			NULL			}
};
# endif /* _FFR_STATSEXT */

static const luaL_Reg dkimf_lua_lib_final[] =
{
	{ "add_header",		dkimf_xs_addheader	},
	{ "add_rcpt",		dkimf_xs_addrcpt	},
	{ "del_header",		dkimf_xs_delheader	},
	{ "del_rcpt",		dkimf_xs_delrcpt	},
	{ "get_clienthost",	dkimf_xs_clienthost	},
	{ "get_clientip",	dkimf_xs_clientip	},
	{ "get_envfrom",	dkimf_xs_getenvfrom	},
	{ "get_fromdomain",	dkimf_xs_fromdomain	},
	{ "get_header",		dkimf_xs_getheader	},
	{ "get_mtasymbol",	dkimf_xs_getsymval	},
	{ "get_rcpt",		dkimf_xs_rcpt		},
	{ "get_rcptarray",	dkimf_xs_rcptarray	},
	{ "get_sigarray",	dkimf_xs_getsigarray	},
	{ "get_sigcount",	dkimf_xs_getsigcount	},
	{ "get_sighandle",	dkimf_xs_getsighandle	},
	{ "internal_ip",	dkimf_xs_internalip	},
	{ "log",		dkimf_xs_log		},
	{ "quarantine",		dkimf_xs_quarantine	},
	{ "parse_field",	dkimf_xs_parsefield	},
# ifdef _FFR_RBL
	{ "rbl_check",		dkimf_xs_rblcheck	},
# endif /* _FFR_RBL */
	{ "rcpt_count",		dkimf_xs_rcptcount	},
	{ "set_reply",		dkimf_xs_setreply	},
	{ "set_result",		dkimf_xs_setresult	},
	{ "sig_bhresult",	dkimf_xs_sigbhresult	},
	{ "sig_bodylength",	dkimf_xs_bodylength	},
	{ "sig_canonlength",	dkimf_xs_canonlength	},
	{ "sig_getdomain",	dkimf_xs_getsigdomain	},
	{ "sig_getidentity",	dkimf_xs_getsigidentity	},
	{ "sig_result",		dkimf_xs_sigresult	},
# ifdef _FFR_REPUTATION
	{ "spam",		dkimf_xs_spam		},
# endif /* _FFR_REPUTATION */
	{ "xtag",		dkimf_xs_xtag		},
	{ NULL,			NULL			}
};
#endif /* DKIMF_LUA_CONTEXT_HOOKS */

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
		*size = io->lua_io_len;
		return io->lua_io_script;
	}
}

/*
**  DKIMF_LUA_WRITER -- extract a compiled script from a Lua state
**
**  Parameters:
**  	l -- Lua state
**  	buf -- buffer being written
**  	sz -- size of buffer 
**  	data -- pointer to a Lua I/O structure
**
**  Return value:
**  	0 on success, !0 on error.
*/

static int
dkimf_lua_writer(lua_State *l, const void *buf, size_t sz, void *data)
{
	struct dkimf_lua_io *io;

	assert(l != NULL);
	assert(buf != NULL);
	assert(data != NULL);

	io = (struct dkimf_lua_io *) data;

	if (io->lua_io_alloc < io->lua_io_len + sz)
	{
		size_t newsz;
		size_t need;
		void *new;

		newsz = io->lua_io_alloc;
		need = io->lua_io_len + sz;
		while (newsz < need)
			newsz += BUFRSZ;

		if (io->lua_io_alloc == 0)
			new = malloc(newsz);
		else
			new = realloc((void *) io->lua_io_script, newsz);

		if (new == NULL)
			return -1;

		io->lua_io_script = new;
		io->lua_io_alloc = newsz;
	}

	memcpy((void *) (io->lua_io_script + io->lua_io_len), buf, sz);
	io->lua_io_len += sz;

	return 0;
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
# if LUA_VERSION_NUM == 502
	else if (nsize != 0 && ptr == NULL)
# else /* LUA_VERSION_NUM == 502 */
	else if (nsize != 0 && osize == 0)
# endif /* LUA_VERSION_NUM == 502 */
	{
		return malloc(nsize);
	}
	else
	{
		return realloc(ptr, nsize);
	}
}

/*
**  DKIMF_LUA_GC_ADD -- add an item for garbage collection
**
**  Parameters:
**  	gc -- garbage collection handle
** 	item -- item to add
**  	type -- item type
**
**  Return value:
**  	None.
*/

void
dkimf_lua_gc_add(struct dkimf_lua_gc *gc, void *item, int type)
{
	struct dkimf_lua_gc_item *new;

	assert(gc != NULL);
	assert(item != NULL);

	new = (struct dkimf_lua_gc_item *) malloc(sizeof *new);
	assert(new != NULL);

	new->gci_item = item;
	new->gci_type = type;
	new->gci_next = NULL;

	if (gc->gc_head == NULL)
		gc->gc_head = new;
	if (gc->gc_tail != NULL)
		gc->gc_tail->gci_next = new;
	gc->gc_tail = new;
}

/*
**  DKIMF_LUA_GC_REMOVE -- remove an item from garbage collection
**
**  Parameters:
**  	gc -- garbage collection handle
** 	item -- item to remove
**
**  Return value:
**  	None.
*/

void
dkimf_lua_gc_remove(struct dkimf_lua_gc *gc, void *item)
{
	struct dkimf_lua_gc_item *cur;
	struct dkimf_lua_gc_item *prev = NULL;

	assert(gc != NULL);
	assert(item != NULL);

	cur = gc->gc_head;

	while (cur != NULL)
	{
		if (cur->gci_item == item)
		{
			if (cur == gc->gc_head)			/* head */
			{
				gc->gc_head = cur->gci_next;
				free(cur);
				cur = gc->gc_head;
			}
			else if (cur == gc->gc_tail)		/* tail */
			{
				prev->gci_next = NULL;
				gc->gc_tail = prev;
				free(cur);
				cur = NULL;
			}
			else					/* middle */
			{
				prev->gci_next = cur->gci_next;
				free(cur);
				cur = prev->gci_next;
			}
		}
		else
		{
			prev = cur;
			cur = cur->gci_next;
		}
	}
}

/*
**  DKIMF_LUA_GC_CLEANUP -- perform garbage collection
**
**  Parameters:
**  	gc -- garbage collection handle
**
**  Return value:
**  	None.
*/

void
dkimf_lua_gc_cleanup(struct dkimf_lua_gc *gc)
{
	struct dkimf_lua_gc_item *cur;
	struct dkimf_lua_gc_item *next;

	assert(gc != NULL);

	cur = gc->gc_head;

	while (cur != NULL)
	{
		switch (cur->gci_type)
		{
		  case DKIMF_LUA_GC_DB:
			(void) dkimf_db_close((DKIMF_DB) cur->gci_item);
			break;

		  default:
			assert(0);
		}

		next = cur->gci_next;
		free(cur);
		cur = next;
	}
}

#ifdef DKIMF_LUA_CONTEXT_HOOKS
/*
**  DKIMF_LUA_SETUP_HOOK -- hook to Lua for handling a message during setup
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	script -- script to run
**  	scriptlen -- length of script; if 0, use strlen()
**  	name -- name of the script (for logging)
**  	lres -- Lua result structure
**  	keep -- where to save the script (or NULL)
**  	funclen -- size of the saved object
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
*/

int
dkimf_lua_setup_hook(void *ctx, const char *script, size_t scriptlen,
                     const char *name, struct dkimf_lua_script_result *lres,
                     void **keep, size_t *funclen)
{
	int status;
	lua_State *l = NULL;
	struct dkimf_lua_io io;
	struct dkimf_lua_gc gc;

	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;
	if (scriptlen == 0)
		io.lua_io_len = strlen(script);
	else
		io.lua_io_len = scriptlen;

	gc.gc_head = NULL;
	gc.gc_tail = NULL;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	luaL_openlibs(l);

	/*
	**  Register functions.
	*/

# if LUA_VERSION_NUM == 502
	luaL_newlib(l, dkimf_lua_lib_setup);
	lua_setglobal(l, "odkim");
# else /* LUA_VERSION_NUM == 502 */
	luaL_register(l, "odkim", dkimf_lua_lib_setup);
# endif /* LUA_VERSION_NUM == 502 */
	lua_pop(l, 1);

	/*
	**  Register constants.
	*/

	/* garbage collection handle */
	lua_pushlightuserdata(l, &gc);
	lua_setglobal(l, DKIMF_GC);

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
	lua_pushnumber(l, DB_SIGNINGTABLE);
	lua_setglobal(l, "DB_SIGNINGTABLE");

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

	/* import other globals */
	dkimf_import_globals(ctx, l);

# if LUA_VERSION_NUM == 502
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name, NULL))
# else /* LUA_VERSION_NUM == 502 */
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
# endif /* LUA_VERSION_NUM == 502 */
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

	if (keep != NULL && funclen != NULL)
	{
		io.lua_io_done = FALSE;
		io.lua_io_script = NULL;
		io.lua_io_len = 0;
		io.lua_io_alloc = 0;

		if (lua_dump(l, dkimf_lua_writer, &io) == 0)
		{
			*keep = (void *) io.lua_io_script;
			*funclen = io.lua_io_len;
		}
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (lua_isstring(l, 1))
		lres->lrs_error = strdup(lua_tostring(l, 1));

	dkimf_lua_gc_cleanup(&gc);

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
**  	scriptlen -- length of script; if 0, use strlen()
**  	name -- name of the script (for logging)
**  	lres -- Lua result structure
**  	keep -- where to save the script (or NULL)
**  	funclen -- size of the saved object
**
**  Return value:
**  	2 -- processing error
**  	1 -- script contains a syntax error
**  	0 -- success
**  	-1 -- memory allocation failure
**
**  Notes:
**  	Called by mlfi_eom() so it can decide whether or not the message
**  	is acceptable.
*/

int
dkimf_lua_screen_hook(void *ctx, const char *script, size_t scriptlen,
                      const char *name, struct dkimf_lua_script_result *lres,
                      void **keep, size_t *funclen)
{
	int status;
	lua_State *l = NULL;
	struct dkimf_lua_io io;
	struct dkimf_lua_gc gc;

	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;
	if (scriptlen == 0)
		io.lua_io_len = strlen(script);
	else
		io.lua_io_len = scriptlen;

	gc.gc_head = NULL;
	gc.gc_tail = NULL;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	luaL_openlibs(l);

	/*
	**  Register functions.
	*/

# if LUA_VERSION_NUM == 502
	luaL_newlib(l, dkimf_lua_lib_screen);
	lua_setglobal(l, "odkim");
# else /* LUA_VERSION_NUM == 502 */
	luaL_register(l, "odkim", dkimf_lua_lib_screen);
# endif /* LUA_VERSION_NUM == 502 */
	lua_pop(l, 1);

	/*
	**  Register constants.
	*/

	/* garbage collection handle */
	lua_pushlightuserdata(l, &gc);
	lua_setglobal(l, DKIMF_GC);

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
	lua_pushnumber(l, DB_SIGNINGTABLE);
	lua_setglobal(l, "DB_SIGNINGTABLE");

	/* milter context */
	lua_pushlightuserdata(l, ctx);
	lua_setglobal(l, "ctx");

	/* import other globals */
	dkimf_import_globals(ctx, l);

# if LUA_VERSION_NUM == 502
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name, NULL))
# else /* LUA_VERSION_NUM == 502 */
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
# endif /* LUA_VERSION_NUM == 502 */
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

	if (keep != NULL && funclen != NULL)
	{
		io.lua_io_done = FALSE;
		io.lua_io_script = NULL;
		io.lua_io_len = 0;
		io.lua_io_alloc = 0;

		if (lua_dump(l, dkimf_lua_writer, &io) == 0)
		{
			*keep = (void *) io.lua_io_script;
			*funclen = io.lua_io_len;
		}
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (lua_isstring(l, 1))
		lres->lrs_error = strdup(lua_tostring(l, 1));

	dkimf_lua_gc_cleanup(&gc);

	lua_close(l);

	return (status == 0 ? 0 : 2);
}

# ifdef _FFR_STATSEXT
/*
**  DKIMF_LUA_STATS_HOOK -- hook to Lua for recording statistics after
**                          verifying has been done
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	script -- script to run
**  	scriptlen -- length of script; if 0, use strlen()
**  	name -- name of the script (for logging)
**  	lres -- Lua result structure
**  	keep -- where to save the script (or NULL)
**  	funclen -- size of the saved object
**
**  Return value:
**  	2 -- processing error
**  	1 -- script contains a syntax error
**  	0 -- success
**  	-1 -- memory allocation failure
**
**  Notes:
**  	Called by mlfi_eom() so it can pass extra statistical parameters
**  	to the stats recording module.
*/

int
dkimf_lua_stats_hook(void *ctx, const char *script, size_t scriptlen,
                     const char *name, struct dkimf_lua_script_result *lres,
                     void **keep, size_t *funclen)
{
	int status;
	lua_State *l = NULL;
	struct dkimf_lua_io io;
	struct dkimf_lua_gc gc;

	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;
	if (scriptlen == 0)
		io.lua_io_len = strlen(script);
	else
		io.lua_io_len = scriptlen;

	gc.gc_head = NULL;
	gc.gc_tail = NULL;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	luaL_openlibs(l);

	/*
	**  Register functions.
	*/

# if LUA_VERSION_NUM == 502
	luaL_newlib(l, dkimf_lua_lib_stats);
	lua_setglobal(l, "odkim");
# else /* LUA_VERSION_NUM == 502 */
	luaL_register(l, "odkim", dkimf_lua_lib_stats);
# endif /* LUA_VERSION_NUM == 502 */
	lua_pop(l, 1);

	/*
	**  Register constants.
	*/

	/* garbage collection handle */
	lua_pushlightuserdata(l, &gc);
	lua_setglobal(l, DKIMF_GC);

	/* milter result codes */
	lua_pushnumber(l, SMFIS_TEMPFAIL);
	lua_setglobal(l, "SMFIS_TEMPFAIL");
	lua_pushnumber(l, SMFIS_ACCEPT);
	lua_setglobal(l, "SMFIS_ACCEPT");
	lua_pushnumber(l, SMFIS_DISCARD);
	lua_setglobal(l, "SMFIS_DISCARD");
	lua_pushnumber(l, SMFIS_REJECT);
	lua_setglobal(l, "SMFIS_REJECT");

	/* signature "bh" result codes */
	lua_pushnumber(l, DKIM_SIGBH_UNTESTED);
	lua_setglobal(l, "DKIM_SIGBH_UNTESTED");
	lua_pushnumber(l, DKIM_SIGBH_MATCH);
	lua_setglobal(l, "DKIM_SIGBH_MATCH");
	lua_pushnumber(l, DKIM_SIGBH_MISMATCH);
	lua_setglobal(l, "DKIM_SIGBH_MISMATCH");

	/* signature error codes */
	lua_pushnumber(l, DKIM_SIGERROR_UNKNOWN);
	lua_setglobal(l, "DKIM_SIGERROR_UNKNOWN");
	lua_pushnumber(l, DKIM_SIGERROR_OK);
	lua_setglobal(l, "DKIM_SIGERROR_OK");
	lua_pushnumber(l, DKIM_SIGERROR_VERSION);
	lua_setglobal(l, "DKIM_SIGERROR_VERSION");
	lua_pushnumber(l, DKIM_SIGERROR_DOMAIN);
	lua_setglobal(l, "DKIM_SIGERROR_DOMAIN");
	lua_pushnumber(l, DKIM_SIGERROR_EXPIRED);
	lua_setglobal(l, "DKIM_SIGERROR_EXPIRED");
	lua_pushnumber(l, DKIM_SIGERROR_FUTURE);
	lua_setglobal(l, "DKIM_SIGERROR_FUTURE");
	lua_pushnumber(l, DKIM_SIGERROR_TIMESTAMPS);
	lua_setglobal(l, "DKIM_SIGERROR_TIMESTAMPS");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_HC);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_HC");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_BC);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_BC");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_A);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_A");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_A);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_A");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_H);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_H");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_L);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_L");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_Q);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_Q");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_QO);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_QO");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_D);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_D");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_D);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_D");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_S);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_S");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_S);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_S");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_B);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_B");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_B);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_B");
	lua_pushnumber(l, DKIM_SIGERROR_CORRUPT_B);
	lua_setglobal(l, "DKIM_SIGERROR_CORRUPT_B");
	lua_pushnumber(l, DKIM_SIGERROR_NOKEY);
	lua_setglobal(l, "DKIM_SIGERROR_NOKEY");
	lua_pushnumber(l, DKIM_SIGERROR_DNSSYNTAX);
	lua_setglobal(l, "DKIM_SIGERROR_DNSSYNTAX");
	lua_pushnumber(l, DKIM_SIGERROR_KEYFAIL);
	lua_setglobal(l, "DKIM_SIGERROR_KEYFAIL");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_BH);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_BH");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_BH);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_BH");
	lua_pushnumber(l, DKIM_SIGERROR_CORRUPT_BH);
	lua_setglobal(l, "DKIM_SIGERROR_CORRUPT_BH");
	lua_pushnumber(l, DKIM_SIGERROR_BADSIG);
	lua_setglobal(l, "DKIM_SIGERROR_BADSIG");
	lua_pushnumber(l, DKIM_SIGERROR_SUBDOMAIN);
	lua_setglobal(l, "DKIM_SIGERROR_SUBDOMAIN");
	lua_pushnumber(l, DKIM_SIGERROR_MULTIREPLY);
	lua_setglobal(l, "DKIM_SIGERROR_MULTIREPLY");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_H);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_H");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_H);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_H");
	lua_pushnumber(l, DKIM_SIGERROR_TOOLARGE_L);
	lua_setglobal(l, "DKIM_SIGERROR_TOOLARGE_L");
	lua_pushnumber(l, DKIM_SIGERROR_MBSFAILED);
	lua_setglobal(l, "DKIM_SIGERROR_MBSFAILED");
	lua_pushnumber(l, DKIM_SIGERROR_KEYVERSION);
	lua_setglobal(l, "DKIM_SIGERROR_KEYVERSION");
	lua_pushnumber(l, DKIM_SIGERROR_KEYUNKNOWNHASH);
	lua_setglobal(l, "DKIM_SIGERROR_KEYUNKNOWNHASH");
	lua_pushnumber(l, DKIM_SIGERROR_KEYHASHMISMATCH);
	lua_setglobal(l, "DKIM_SIGERROR_KEYHASHMISMATCH");
	lua_pushnumber(l, DKIM_SIGERROR_NOTEMAILKEY);
	lua_setglobal(l, "DKIM_SIGERROR_NOTEMAILKEY");
	lua_pushnumber(l, DKIM_SIGERROR_KEYTYPEMISSING);
	lua_setglobal(l, "DKIM_SIGERROR_KEYTYPEMISSING");
	lua_pushnumber(l, DKIM_SIGERROR_KEYTYPEUNKNOWN);
	lua_setglobal(l, "DKIM_SIGERROR_KEYTYPEUNKNOWN");
	lua_pushnumber(l, DKIM_SIGERROR_KEYREVOKED);
	lua_setglobal(l, "DKIM_SIGERROR_KEYREVOKED");
	lua_pushnumber(l, DKIM_SIGERROR_KEYDECODE);
	lua_setglobal(l, "DKIM_SIGERROR_KEYDECODE");

	/* milter context */
	lua_pushlightuserdata(l, ctx);
	lua_setglobal(l, "ctx");

	/* import other globals */
	dkimf_import_globals(ctx, l);

# if LUA_VERSION_NUM == 502
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name, NULL))
# else /* LUA_VERSION_NUM == 502 */
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
# endif /* LUA_VERSION_NUM == 502 */
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

	if (keep != NULL && funclen != NULL)
	{
		io.lua_io_done = FALSE;
		io.lua_io_script = NULL;
		io.lua_io_len = 0;
		io.lua_io_alloc = 0;

		if (lua_dump(l, dkimf_lua_writer, &io) == 0)
		{
			*keep = (void *) io.lua_io_script;
			*funclen = io.lua_io_len;
		}
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (lua_isstring(l, 1))
		lres->lrs_error = strdup(lua_tostring(l, 1));

	dkimf_lua_gc_cleanup(&gc);

	lua_close(l);

	return (status == 0 ? 0 : 2);
}
# endif /* _FFR_STATSEXT */

/*
**  DKIMF_LUA_FINAL_HOOK -- hook to Lua for handling a message after all
**                          signing and verifying has been done
**
**  Parameters:
**  	ctx -- session context, for making calls back to opendkim.c
**  	script -- script to run
**  	scriptlen -- length of script; if 0, use strlen()
**  	name -- name of the script (for logging)
**  	lres -- Lua result structure
**  	keep -- where to save the script (or NULL)
**  	funclen -- size of the saved object
**
**  Return value:
**  	2 -- processing error
**  	1 -- script contains a syntax error
**  	0 -- success
**  	-1 -- memory allocation failure
**
**  Notes:
**  	Called by mlfi_eom() so it can decide whether or not the message
**  	is acceptable.
*/

int
dkimf_lua_final_hook(void *ctx, const char *script, size_t scriptlen,
                     const char *name, struct dkimf_lua_script_result *lres,
                     void **keep, size_t *funclen)
{
	int status;
	lua_State *l = NULL;
	struct dkimf_lua_io io;
	struct dkimf_lua_gc gc;

	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;
	if (scriptlen == 0)
		io.lua_io_len = strlen(script);
	else
		io.lua_io_len = scriptlen;

	gc.gc_head = NULL;
	gc.gc_tail = NULL;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	luaL_openlibs(l);

	/*
	**  Register functions.
	*/

# if LUA_VERSION_NUM == 502
	luaL_newlib(l, dkimf_lua_lib_final);
	lua_setglobal(l, "odkim");
# else /* LUA_VERSION_NUM == 502 */
	luaL_register(l, "odkim", dkimf_lua_lib_final);
# endif /* LUA_VERSION_NUM == 502 */
	lua_pop(l, 1);

	/*
	**  Register constants.
	*/

	/* garbage collection handle */
	lua_pushlightuserdata(l, &gc);
	lua_setglobal(l, DKIMF_GC);

	/* milter result codes */
	lua_pushnumber(l, SMFIS_TEMPFAIL);
	lua_setglobal(l, "SMFIS_TEMPFAIL");
	lua_pushnumber(l, SMFIS_ACCEPT);
	lua_setglobal(l, "SMFIS_ACCEPT");
	lua_pushnumber(l, SMFIS_DISCARD);
	lua_setglobal(l, "SMFIS_DISCARD");
	lua_pushnumber(l, SMFIS_REJECT);
	lua_setglobal(l, "SMFIS_REJECT");

	/* signature "bh" result codes */
	lua_pushnumber(l, DKIM_SIGBH_UNTESTED);
	lua_setglobal(l, "DKIM_SIGBH_UNTESTED");
	lua_pushnumber(l, DKIM_SIGBH_MATCH);
	lua_setglobal(l, "DKIM_SIGBH_MATCH");
	lua_pushnumber(l, DKIM_SIGBH_MISMATCH);
	lua_setglobal(l, "DKIM_SIGBH_MISMATCH");

	/* signature error codes */
	lua_pushnumber(l, DKIM_SIGERROR_UNKNOWN);
	lua_setglobal(l, "DKIM_SIGERROR_UNKNOWN");
	lua_pushnumber(l, DKIM_SIGERROR_OK);
	lua_setglobal(l, "DKIM_SIGERROR_OK");
	lua_pushnumber(l, DKIM_SIGERROR_VERSION);
	lua_setglobal(l, "DKIM_SIGERROR_VERSION");
	lua_pushnumber(l, DKIM_SIGERROR_DOMAIN);
	lua_setglobal(l, "DKIM_SIGERROR_DOMAIN");
	lua_pushnumber(l, DKIM_SIGERROR_EXPIRED);
	lua_setglobal(l, "DKIM_SIGERROR_EXPIRED");
	lua_pushnumber(l, DKIM_SIGERROR_FUTURE);
	lua_setglobal(l, "DKIM_SIGERROR_FUTURE");
	lua_pushnumber(l, DKIM_SIGERROR_TIMESTAMPS);
	lua_setglobal(l, "DKIM_SIGERROR_TIMESTAMPS");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_HC);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_HC");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_BC);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_BC");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_A);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_A");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_A);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_A");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_H);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_H");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_L);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_L");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_Q);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_Q");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_QO);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_QO");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_D);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_D");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_D);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_D");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_S);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_S");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_S);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_S");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_B);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_B");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_B);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_B");
	lua_pushnumber(l, DKIM_SIGERROR_CORRUPT_B);
	lua_setglobal(l, "DKIM_SIGERROR_CORRUPT_B");
	lua_pushnumber(l, DKIM_SIGERROR_NOKEY);
	lua_setglobal(l, "DKIM_SIGERROR_NOKEY");
	lua_pushnumber(l, DKIM_SIGERROR_DNSSYNTAX);
	lua_setglobal(l, "DKIM_SIGERROR_DNSSYNTAX");
	lua_pushnumber(l, DKIM_SIGERROR_KEYFAIL);
	lua_setglobal(l, "DKIM_SIGERROR_KEYFAIL");
	lua_pushnumber(l, DKIM_SIGERROR_MISSING_BH);
	lua_setglobal(l, "DKIM_SIGERROR_MISSING_BH");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_BH);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_BH");
	lua_pushnumber(l, DKIM_SIGERROR_CORRUPT_BH);
	lua_setglobal(l, "DKIM_SIGERROR_CORRUPT_BH");
	lua_pushnumber(l, DKIM_SIGERROR_BADSIG);
	lua_setglobal(l, "DKIM_SIGERROR_BADSIG");
	lua_pushnumber(l, DKIM_SIGERROR_SUBDOMAIN);
	lua_setglobal(l, "DKIM_SIGERROR_SUBDOMAIN");
	lua_pushnumber(l, DKIM_SIGERROR_MULTIREPLY);
	lua_setglobal(l, "DKIM_SIGERROR_MULTIREPLY");
	lua_pushnumber(l, DKIM_SIGERROR_EMPTY_H);
	lua_setglobal(l, "DKIM_SIGERROR_EMPTY_H");
	lua_pushnumber(l, DKIM_SIGERROR_INVALID_H);
	lua_setglobal(l, "DKIM_SIGERROR_INVALID_H");
	lua_pushnumber(l, DKIM_SIGERROR_TOOLARGE_L);
	lua_setglobal(l, "DKIM_SIGERROR_TOOLARGE_L");
	lua_pushnumber(l, DKIM_SIGERROR_MBSFAILED);
	lua_setglobal(l, "DKIM_SIGERROR_MBSFAILED");
	lua_pushnumber(l, DKIM_SIGERROR_KEYVERSION);
	lua_setglobal(l, "DKIM_SIGERROR_KEYVERSION");
	lua_pushnumber(l, DKIM_SIGERROR_KEYUNKNOWNHASH);
	lua_setglobal(l, "DKIM_SIGERROR_KEYUNKNOWNHASH");
	lua_pushnumber(l, DKIM_SIGERROR_KEYHASHMISMATCH);
	lua_setglobal(l, "DKIM_SIGERROR_KEYHASHMISMATCH");
	lua_pushnumber(l, DKIM_SIGERROR_NOTEMAILKEY);
	lua_setglobal(l, "DKIM_SIGERROR_NOTEMAILKEY");
	lua_pushnumber(l, DKIM_SIGERROR_KEYTYPEMISSING);
	lua_setglobal(l, "DKIM_SIGERROR_KEYTYPEMISSING");
	lua_pushnumber(l, DKIM_SIGERROR_KEYTYPEUNKNOWN);
	lua_setglobal(l, "DKIM_SIGERROR_KEYTYPEUNKNOWN");
	lua_pushnumber(l, DKIM_SIGERROR_KEYREVOKED);
	lua_setglobal(l, "DKIM_SIGERROR_KEYREVOKED");
	lua_pushnumber(l, DKIM_SIGERROR_KEYDECODE);
	lua_setglobal(l, "DKIM_SIGERROR_KEYDECODE");

	/* milter context */
	lua_pushlightuserdata(l, ctx);
	lua_setglobal(l, "ctx");

	/* import other globals */
	dkimf_import_globals(ctx, l);

# if LUA_VERSION_NUM == 502
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name, NULL))
# else /* LUA_VERSION_NUM == 502 */
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, name))
# endif /* LUA_VERSION_NUM == 502 */
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

	if (keep != NULL && funclen != NULL)
	{
		io.lua_io_done = FALSE;
		io.lua_io_script = NULL;
		io.lua_io_len = 0;
		io.lua_io_alloc = 0;

		if (lua_dump(l, dkimf_lua_writer, &io) == 0)
		{
			*keep = (void *) io.lua_io_script;
			*funclen = io.lua_io_len;
		}
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (lua_isstring(l, 1))
		lres->lrs_error = strdup(lua_tostring(l, 1));

	dkimf_lua_gc_cleanup(&gc);

	lua_close(l);

	return (status == 0 ? 0 : 2);
}
#endif /* DKIMF_LUA_CONTEXT_HOOKS */

/*
**  DKIMF_LUA_DB_HOOK -- hook to Lua for handling a DB query
**
**  Parameters:
**  	script -- script to run
**  	scriptlen -- length of script; if 0, use strlen()
**  	query -- query string
**  	lres -- Lua result structure
**  	keep -- where to save the script (or NULL)
**  	funclen -- size of the saved object
**
**  Return value:
**  	2 -- processing error
**  	1 -- script contains a syntax error
**  	0 -- success
**  	-1 -- memory allocation failure
*/

int
dkimf_lua_db_hook(const char *script, size_t scriptlen, const char *query,
                  struct dkimf_lua_script_result *lres, void **keep,
                  size_t *funclen)
{
	int status;
	struct dkimf_lua_io io;
	lua_State *l = NULL;

	assert(script != NULL);
	assert(lres != NULL);

	io.lua_io_done = FALSE;
	io.lua_io_script = script;
	if (scriptlen == 0)
		io.lua_io_len = strlen(script);
	else
		io.lua_io_len = scriptlen;

	l = lua_newstate(dkimf_lua_alloc, NULL);
	if (l == NULL)
		return -1;

	luaL_openlibs(l);

	/* query string */
	if (query == NULL)
		lua_pushnil(l);
	else
		lua_pushstring(l, query);
	lua_setglobal(l, "query");

# if LUA_VERSION_NUM == 502
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, script, NULL))
# else /* LUA_VERSION_NUM == 502 */
	switch (lua_load(l, dkimf_lua_reader, (void *) &io, script))
# endif /* LUA_VERSION_NUM == 502 */
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

	if (keep != NULL && funclen != NULL)
	{
		io.lua_io_done = FALSE;
		io.lua_io_script = NULL;
		io.lua_io_len = 0;
		io.lua_io_alloc = 0;

		if (lua_dump(l, dkimf_lua_writer, &io) == 0)
		{
			*keep = (void *) io.lua_io_script;
			*funclen = io.lua_io_len;
		}
	}

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (status != 0 && lua_isstring(l, 1))
	{
		lres->lrs_error = strdup(lua_tostring(l, 1));
		lres->lrs_rcount = 0;
	}
	else if (status == 0)
	{
		size_t asz;

		lres->lrs_rcount = lua_gettop(l);

		asz = sizeof(char *) * lres->lrs_rcount;
		lres->lrs_results = (char **) malloc(asz);
		if (lres->lrs_results != NULL)
		{
			int c;

			for (c = 0; c < lres->lrs_rcount; c++)
			{
				lres->lrs_results[c] = strdup(lua_tostring(l,
				                                           c + 1));
			}
		}
	}

	lua_close(l);

	return (status == 0 ? 0 : 2);
}
#endif /* USE_LUA */
