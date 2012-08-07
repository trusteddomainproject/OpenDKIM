/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _DKIM_POLICY_H_
#define _DKIM_POLICY_H_

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
