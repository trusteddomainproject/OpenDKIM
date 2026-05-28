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

extern void *dkim_malloc (DKIM_LIB *, void *, size_t);
extern void dkim_mfree (DKIM_LIB *, void *, void *);
extern unsigned char *dkim_strdup (DKIM *, const unsigned char *, size_t);
extern DKIM_STAT dkim_tmpfile (DKIM *, int *, _Bool);

extern void dkim_dstring_blank (struct dkim_dstring *);
extern _Bool dkim_dstring_cat (struct dkim_dstring *, u_char *);
extern _Bool dkim_dstring_cat1 (struct dkim_dstring *, int);
extern _Bool dkim_dstring_catn (struct dkim_dstring *, u_char *, size_t);
extern _Bool dkim_dstring_copy (struct dkim_dstring *, u_char *);
extern void dkim_dstring_free (struct dkim_dstring *);
extern u_char *dkim_dstring_get (struct dkim_dstring *);
extern int dkim_dstring_len (struct dkim_dstring *);
extern struct dkim_dstring *dkim_dstring_new (DKIM *, int, int);
extern size_t dkim_dstring_printf (struct dkim_dstring *dstr, char *fmt,
                                       ...);

#endif /* _DKIM_UTIL_H_ */
