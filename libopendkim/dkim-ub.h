/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_UB_H_
#define _DKIM_UB_H_

#ifndef lint
static char dkim_ub_h_id[] = "@(#)$Id: dkim-ub.h,v 1.2 2009/07/20 21:41:08 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

/* libdkim includes */
#include "dkim-types.h"

/* prototypes */
extern int dkim_unbound_add_trustanchor __P((DKIM_LIB *lib, char *tafile));
extern int dkim_unbound_close __P((DKIM_LIB *lib));
extern int dkim_unbound_init __P((DKIM_LIB *lib));
extern int dkim_unbound_queue __P((DKIM *dkim, char *name, int type,
                                   u_char *buf, size_t buflen,
                                   struct dkim_unbound_cb_data *cbdata));
extern int dkim_unbound_wait __P((DKIM *dkim,
                                  struct dkim_unbound_cb_data *ubdata));

#endif /* _DKIM_UB_H_ */
