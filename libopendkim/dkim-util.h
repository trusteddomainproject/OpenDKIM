/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _DKIM_UTIL_H_
#define _DKIM_UTIL_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libopendkim includes */
#include "dkim.h"

/* macros */
#define	DKIM_MALLOC(x,y)	dkim_malloc((x)->dkim_libhandle, \
				            (x)->dkim_closure, y)
#define	DKIM_FREE(x,y)		dkim_mfree((x)->dkim_libhandle, \
				           (x)->dkim_closure, y)

extern void *dkim_malloc __P((DKIM_LIB *, void *, size_t));
extern void dkim_mfree __P((DKIM_LIB *, void *, void *));
extern unsigned char *dkim_strdup __P((DKIM *, const unsigned char *, size_t));
extern DKIM_STAT dkim_tmpfile __P((DKIM *, int *, _Bool));

extern void dkim_dstring_blank __P((struct dkim_dstring *));
extern _Bool dkim_dstring_cat __P((struct dkim_dstring *, u_char *));
extern _Bool dkim_dstring_cat1 __P((struct dkim_dstring *, int));
extern _Bool dkim_dstring_catn __P((struct dkim_dstring *, u_char *, size_t));
extern _Bool dkim_dstring_copy __P((struct dkim_dstring *, u_char *));
extern void dkim_dstring_free __P((struct dkim_dstring *));
extern u_char *dkim_dstring_get __P((struct dkim_dstring *));
extern int dkim_dstring_len __P((struct dkim_dstring *));
extern struct dkim_dstring *dkim_dstring_new __P((DKIM *, int, int));
extern size_t dkim_dstring_printf __P((struct dkim_dstring *dstr, char *fmt,
                                       ...));

#endif /* _DKIM_UTIL_H_ */
