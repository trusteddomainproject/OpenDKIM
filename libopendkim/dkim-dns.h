/*
**  Copyright (c) 2010, 2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _DKIM_DNS_H_
#define _DKIM_DNS_H_

/* libopendkim includes */
#include "dkim.h"

/* prototypes */
extern int dkim_res_cancel __P((void *, void *));
extern void dkim_res_close __P((void *));
extern int dkim_res_init __P((void **));
extern int dkim_res_nslist __P((void *, const char *));
extern int dkim_res_query __P((void *, int, unsigned char *, unsigned char *,
                               size_t, void **));
extern int dkim_res_waitreply __P((void *, void *, struct timeval *,
                                   size_t *, int *, int *));

#endif /* ! _DKIM_DNS_H_ */
