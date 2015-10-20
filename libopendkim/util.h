/*
**  Copyright (c) 2005, 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, 2015, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/time.h>
#ifdef USE_UNBOUND
# include <sys/select.h>
#endif /* USE_UNBOUND */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* prototypes */
extern int dkim_addrcmp __P((u_char *, u_char *));
extern int dkim_check_dns_reply __P((unsigned char *ansbuf, size_t anslen,
                                     int xclass, int xtype));
extern void dkim_clobber_array __P((char **));
extern void dkim_collapse __P((u_char *));
extern const char **dkim_copy_array __P((char **));
extern _Bool dkim_hdrlist __P((u_char *, size_t, u_char **, _Bool));
extern int dkim_hexchar __P((int c));
extern void dkim_lowerhdr __P((u_char *));
extern void dkim_min_timeval __P((struct timeval *, struct timeval *,
                                  struct timeval *, struct timeval **));
extern int dkim_qp_decode __P((u_char *, u_char *, int));
extern int dkim_qp_encode __P((u_char *, u_char *, int));
extern _Bool dkim_strisprint __P((u_char *));

#ifdef NEED_FAST_STRTOUL
extern unsigned long dkim_strtoul __P((const char *str, char **endptr,
                                       int base));
extern unsigned long long dkim_strtoull __P((const char *str, char **endptr,
                                             int base));
#endif /* NEED_FAST_STRTOUL */

#endif /* ! _UTIL_H_ */
