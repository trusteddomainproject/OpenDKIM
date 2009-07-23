/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_REP_H_
#define _DKIM_REP_H_

#ifndef lint
static char dkim_rep_h_id[] = "@(#)$Id: dkim-rep.h,v 1.2 2009/07/23 17:40:23 cm-msk Exp $";
#endif /* !lint */

/* libopendkim includes */
#include "dkim.h"

/* prototypes */
extern int dkim_reputation __P((DKIM *, u_char *, u_char *, char *,
                                char *qroot, int *rep));

#endif /* ! _DKIM_REP_H_ */
