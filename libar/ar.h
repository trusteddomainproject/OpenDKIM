/*
**  Copyright (c) 2004, 2005, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _AR_H_
#define _AR_H_

#ifndef lint
static char ar_h_id[] = "@(#)$Id: ar.h,v 1.1 2009/07/16 18:56:09 cm-msk Exp $";
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

#define	AR_STAT_ERROR		(-1)		/* error in transit */
#define	AR_STAT_SUCCESS		0		/* reply available */
#define	AR_STAT_NOREPLY		1		/* reply not available (yet) */
#define	AR_STAT_EXPIRED		2		/* no reply, query expired */

#define QUERY_ERRNO_TOOBIG	(-1)		/* query too large */
#define QUERY_ERRNO_RETRIES	(-2)		/* too many retries */

#define	AR_MAXTIMEOUT		10000000	/* max. allowed timeout (s) */


/* PROTOTYPES */
extern AR_QUERY ar_addquery(AR_LIB, char *, int, int, int, unsigned char *,
                            size_t, int *, struct timeval *);
extern int ar_cancelquery(AR_LIB, AR_QUERY);
extern char *ar_strerror(int err);
extern int ar_waitreply(AR_LIB, AR_QUERY, size_t *, struct timeval *);
extern AR_LIB ar_init(ar_malloc_t *, ar_free_t *, void *, int);
extern void ar_recycle(AR_LIB, AR_QUERY);
extern int ar_resend(AR_LIB, AR_QUERY);
extern void ar_setmaxretry(AR_LIB lib, int new, int *old);
extern void ar_setretry(AR_LIB lib, struct timeval *new, struct timeval *old);
extern int ar_shutdown(AR_LIB);

#endif /* ! _AR_H_ */
