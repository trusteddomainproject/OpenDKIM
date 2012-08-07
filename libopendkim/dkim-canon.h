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
extern DKIM_STAT dkim_add_canon __P((DKIM *, _Bool, dkim_canon_t, int,
                                     u_char *, struct dkim_header *,
                                     ssize_t length, DKIM_CANON **));
extern DKIM_STAT dkim_canon_bodychunk __P((DKIM *, u_char *, size_t));
extern void dkim_canon_cleanup __P((DKIM *));
extern DKIM_STAT dkim_canon_closebody __P((DKIM *));
extern DKIM_STAT dkim_canon_getfinal __P((DKIM_CANON *, u_char **, size_t *));
extern DKIM_STAT dkim_canon_gethashes __P((DKIM_SIGINFO *, void **, size_t *,
                                           void **, size_t *));
extern DKIM_STAT dkim_canon_header_string __P((struct dkim_dstring *,
                                               dkim_canon_t, unsigned char *,
                                               size_t, _Bool));
extern DKIM_STAT dkim_canon_init __P((DKIM *, _Bool, _Bool));
extern u_long dkim_canon_minbody __P((DKIM *));
extern DKIM_STAT dkim_canon_runheaders __P((DKIM *));
extern int dkim_canon_selecthdrs __P((DKIM *, u_char *, struct dkim_header **,
                                      int));
extern DKIM_STAT dkim_canon_signature __P((DKIM *, struct dkim_header *));

#endif /* ! _DKIM_CANON_H_ */
