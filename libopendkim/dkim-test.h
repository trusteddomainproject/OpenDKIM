/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_TEST_H_
#define _DKIM_TEST_H_

#ifndef lint
static char dkim_test_h_id[] = "@(#)$Id: dkim-test.h,v 1.3 2009/11/06 22:30:13 cm-msk Exp $";
#endif /* !lint */

/* libopendkim includes */
#include "dkim.h"

/* prototypes */
extern size_t dkim_test_dns_get __P((DKIM *, u_char *, size_t));
extern int dkim_test_dns_put __P((DKIM *, int, int, int, u_char *, u_char *));

#endif /* ! _DKIM_TEST_H_ */
