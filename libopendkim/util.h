/*
**  Copyright (c) 2005, 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#ifndef lint
static char util_h_id[] = "@(#)$Id: util.h,v 1.1 2009/07/16 19:12:04 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/time.h>
#ifdef USE_UNBOUND
# include <sys/select.h>
#endif /* USE_UNBOUND */

/* libsm includes */
#include <sm/gen.h>
#include <sm/types.h>
#include <sm/cdefs.h>

/* prototypes */
extern int dkim_addrcmp __P((u_char *, u_char *));
extern int dkim_check_dns_reply __P((unsigned char *ansbuf, size_t anslen,
                                     int xclass, int xtype));
extern void dkim_collapse __P((u_char *));
extern bool dkim_hdrlist __P((u_char *, size_t, u_char **, bool));
extern int dkim_hexchar __P((int c));
extern void dkim_lowerhdr __P((u_char *));
extern int dkim_qp_decode __P((u_char *, u_char *, int));
#ifdef USE_UNBOUND
extern bool dkim_timespec_past __P((struct timespec *tv));
extern int dkim_wait_fd __P((int fd, struct timespec *until));
#endif /* USE_UNBOUND */

#ifdef NEED_FAST_STRTOUL
extern unsigned long dkim_strtoul __P((const char *str, char **endptr,
                                       int base));
extern unsigned long long dkim_strtoull __P((const char *str, char **endptr,
                                             int base));
#endif /* NEED_FAST_STRTOUL */

#endif /* ! _UTIL_H_ */
