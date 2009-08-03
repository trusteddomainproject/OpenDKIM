/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_INTERNAL_H_
#define _DKIM_INTERNAL_H_

#ifndef lint
static char dkim_internal_h_id[] = "@(#)$Id: dkim-internal.h,v 1.1 2009/08/03 20:50:48 cm-msk Exp $";
#endif /* !lint */

/* libopendkim includes */
#include "dkim.h"

/* prototypes */
extern DKIM_STAT dkim_process_set __P((DKIM *, dkim_set_t, u_char *, size_t,
                                       void *, _Bool));
extern DKIM_STAT dkim_siglist_setup __P((DKIM *));

#endif /* ! _DKIM_INTERNAL_H_ */
