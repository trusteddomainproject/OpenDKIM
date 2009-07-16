/*
**  Copyright (c) 2005, 2007 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_KEYS_H_
#define _DKIM_KEYS_H_

#ifndef lint
static char dkim_keys_h_id[] = "@(#)$Id: dkim-keys.h,v 1.1 2009/07/16 19:12:03 cm-msk Exp $";
#endif /* !lint */

/* libdkim includes */
#include "dkim.h"

/* prototypes */
extern DKIM_STAT dkim_get_key_dns __P((DKIM *, DKIM_SIGINFO *, u_char *,
                                       size_t));
extern DKIM_STAT dkim_get_key_file __P((DKIM *, DKIM_SIGINFO *, u_char *,
                                        size_t));

#endif /* ! _DKIM_KEYS_H_ */
