/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-lua.h,v 1.1.2.7 2009/11/27 23:23:02 cm-msk Exp $
*/

#ifndef _OPENDKIM_LUA_H_
#define _OPENDKIM_LUA_H_

#ifndef lint
static char opendkim_lua_h_id[] = "@(#)$Id: opendkim-lua.h,v 1.1.2.7 2009/11/27 23:23:02 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

/* types */
struct dkimf_lua_script_result
{
	char *	lrs_error;
};

/* prototypes */
extern int dkimf_lua_final_hook __P((void *, const char *, const char *,
                                     struct dkimf_lua_script_result *));
extern int dkimf_lua_screen_hook __P((void *, const char *, const char *,
                                      struct dkimf_lua_script_result *));
extern int dkimf_lua_setup_hook __P((void *, const char *, const char *,
                                     struct dkimf_lua_script_result *));

#endif /* _OPENDKIM_LUA_H_ */
