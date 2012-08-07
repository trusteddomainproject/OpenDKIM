/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _DKIM_TEST_H_
#define _DKIM_TEST_H_

/* libopendkim includes */
#include "dkim.h"

/* prototypes */
extern size_t dkim_test_dns_get __P((DKIM *, u_char *, size_t));
extern int dkim_test_dns_put __P((DKIM *, int, int, int, u_char *, u_char *));

#endif /* ! _DKIM_TEST_H_ */
