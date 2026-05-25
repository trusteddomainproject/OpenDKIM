/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _DKIM_CANON_H_
#define _DKIM_CANON_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libopendkim includes */
#include "dkim.h"

#define	DKIM_HASHBUFSIZE	4096

/* prototypes */
extern DKIM_STAT dkim_add_canon (DKIM *, _Bool, dkim_canon_t, int,
                                     u_char *, struct dkim_header *,
                                     ssize_t length, DKIM_CANON **);
extern DKIM_STAT dkim_canon_bodychunk (DKIM *, u_char *, size_t);
extern void dkim_canon_cleanup (DKIM *);
extern DKIM_STAT dkim_canon_closebody (DKIM *);
extern DKIM_STAT dkim_canon_getfinal (DKIM_CANON *, u_char **, size_t *);
extern DKIM_STAT dkim_canon_gethashes (DKIM_SIGINFO *, void **, size_t *,
                                           void **, size_t *);
extern DKIM_STAT dkim_canon_header_string (struct dkim_dstring *,
                                               dkim_canon_t, unsigned char *,
                                               size_t, _Bool);
extern DKIM_STAT dkim_canon_init (DKIM *, _Bool, _Bool);
extern u_long dkim_canon_minbody (DKIM *);
extern DKIM_STAT dkim_canon_runheaders (DKIM *);
extern int dkim_canon_selecthdrs (DKIM *, u_char *, struct dkim_header **,
                                      int);
extern DKIM_STAT dkim_canon_signature (DKIM *, struct dkim_header *);

#endif /* ! _DKIM_CANON_H_ */
