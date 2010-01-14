/*
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-lua.h,v 1.2 2010/01/14 05:58:57 cm-msk Exp $
*/

#ifndef _OPENDKIM_LUA_H_
#define _OPENDKIM_LUA_H_

#ifndef lint
static char opendkim_lua_h_id[] = "@(#)$Id: opendkim-lua.h,v 1.2 2010/01/14 05:58:57 cm-msk Exp $";
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
