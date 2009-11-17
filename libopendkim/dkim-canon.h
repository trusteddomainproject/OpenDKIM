/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_CANON_H_
#define _DKIM_CANON_H_

#ifndef lint
static char dkim_canon_h_id[] = "@(#)$Id: dkim-canon.h,v 1.5 2009/11/17 20:09:21 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <stdbool.h>

/* libopendkim includes */
#include "dkim.h"

#define	DKIM_HASHBUFSIZE	4096

/* prototypes */
extern DKIM_STAT dkim_add_canon __P((DKIM *, _Bool, dkim_canon_t, int,
                                     u_char *, struct dkim_header *,
                                     off_t length, DKIM_CANON **cout));
extern DKIM_STAT dkim_canon_bodychunk __P((DKIM *, u_char *, size_t));
extern void dkim_canon_cleanup __P((DKIM *));
extern DKIM_STAT dkim_canon_closebody __P((DKIM *));
extern DKIM_STAT dkim_canon_getfinal __P((DKIM_CANON *, u_char **, size_t *));
extern DKIM_STAT dkim_canon_init __P((DKIM *, _Bool, _Bool));
extern u_long dkim_canon_minbody __P((DKIM *));
extern DKIM_STAT dkim_canon_runheaders __P((DKIM *));
extern DKIM_STAT dkim_canon_signature __P((DKIM *, struct dkim_header *));

#endif /* ! _DKIM_CANON_H_ */
