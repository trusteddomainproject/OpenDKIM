/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_POLICY_H_
#define _DKIM_POLICY_H_

#ifndef lint
static char dkim_policy_h_id[] = "@(#)$Id: dkim-policy.h,v 1.4.58.1 2010/10/27 21:43:08 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libopendkim includes */
#include "dkim.h"

/* prototypes */
extern int dkim_get_policy_dns __P((DKIM *, u_char *, _Bool, u_char *,
                                    size_t, int *));
extern int dkim_get_policy_file __P((DKIM *, u_char *, u_char *,
                                     size_t, int *));

#endif /* ! _DKIM_POLICY_H_ */
