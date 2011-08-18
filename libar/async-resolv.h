/*
**  Copyright (c) 2004, 2005, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _ASYNC_RESOLV_H_
#define _ASYNC_RESOLV_H_

#ifndef lint
static char async_resolv_h_id[] = "@(#)$Id: ar.h,v 1.4 2010/09/02 05:10:57 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/time.h>

/* useful stuff */
#ifndef NULL
# define NULL	0
#endif /* ! NULL */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */

/* DATA TYPES */
struct ar_libhandle;
typedef struct ar_libhandle * AR_LIB;

struct ar_query;
typedef struct ar_query * AR_QUERY;

/* TYPES */
typedef void *ar_malloc_t(void *, size_t);
typedef void ar_free_t(void *, void *);

/* DEFINITIONS */
#define	AR_FLAG_USETCP		0x01		/* use TCP instead of UDP */
#define	AR_FLAG_DEAD		0x02		/* service now unavailable */
#define	AR_FLAG_TRUNCCHECK	0x04		/* limited truncation checks */
#define	AR_FLAG_RECONNECT	0x08		/* pending reconnect */
#define	AR_FLAG_TRACELOGGING	0x10		/* debug logging */

#define	AR_STAT_ERROR		(-1)		/* error in transit */
#define	AR_STAT_SUCCESS		0		/* reply available */
#define	AR_STAT_NOREPLY		1		/* reply not available (yet) */
#define	AR_STAT_EXPIRED		2		/* no reply, query expired */

#define QUERY_ERRNO_TOOBIG	(-1)		/* query too large */
#define QUERY_ERRNO_RETRIES	(-2)		/* too many retries */
#define QUERY_ERRNO_SERVICE	(-3)		/* lost contact with DNS */

#define	AR_DEFREVIVIFY		2		/* how long to play dead */
#define	AR_MAXTIMEOUT		10000000	/* max. allowed timeout (s) */

/* PROTOTYPES */
extern AR_QUERY ar_addquery(AR_LIB, char *, int, int, int, unsigned char *,
                            size_t, int *, struct timeval *);
extern int ar_cancelquery(AR_LIB, AR_QUERY);
extern char *ar_strerror(int);
extern int ar_waitreply(AR_LIB, AR_QUERY, size_t *, struct timeval *);
extern AR_LIB ar_init(ar_malloc_t *, ar_free_t *, void *, int);
extern void ar_recycle(AR_LIB, AR_QUERY);
extern int ar_resend(AR_LIB, AR_QUERY);
extern void ar_setmaxretry(AR_LIB, int, int *);
extern void ar_setretry(AR_LIB, struct timeval *, struct timeval *);
extern int ar_shutdown(AR_LIB);

#endif /* ! _ASYNC_RESOLV_H_ */
