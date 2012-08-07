/*
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _OPENDKIM_LUA_H_
#define _OPENDKIM_LUA_H_

/* system includes */
#include <sys/types.h>

/* types */
struct dkimf_lua_script_result
{
	int	lrs_rcount;
	char *	lrs_error;
	char **	lrs_results;
};

struct dkimf_lua_gc_item
{
	int				gci_type;
	void *				gci_item;
	struct dkimf_lua_gc_item *	gci_next;
};

struct dkimf_lua_gc
{
	struct dkimf_lua_gc_item *	gc_head;
	struct dkimf_lua_gc_item *	gc_tail;
};

/* macros */
#define	DKIMF_GC		"_DKIMF_GC"
#define	DKIMF_LUA_GC_DB		1

/* prototypes */
extern int dkimf_lua_db_hook __P((const char *, size_t, const char *,
                                  struct dkimf_lua_script_result *,
                                  void **, size_t *));
extern int dkimf_lua_final_hook __P((void *, const char *, size_t,
                                     const char *,
                                     struct dkimf_lua_script_result *,
                                     void **, size_t *));
extern void dkimf_lua_gc_add __P((struct dkimf_lua_gc *g, void *, int));
extern void dkimf_lua_gc_cleanup __P((struct dkimf_lua_gc *));
extern void dkimf_lua_gc_remove __P((struct dkimf_lua_gc *, void *));
extern int dkimf_lua_screen_hook __P((void *, const char *, size_t,
                                      const char *,
                                      struct dkimf_lua_script_result *,
                                      void **, size_t *));
extern int dkimf_lua_setup_hook __P((void *, const char *, size_t,
                                     const char *,
                                     struct dkimf_lua_script_result *,
                                     void **, size_t *));
#ifdef _FFR_STATSEXT
extern int dkimf_lua_stats_hook __P((void *, const char *, size_t,
                                     const char *,
                                     struct dkimf_lua_script_result *,
                                     void **, size_t *));
#endif /* _FFR_STATSEXT */

#endif /* _OPENDKIM_LUA_H_ */
