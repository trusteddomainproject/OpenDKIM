/*
**  Copyright (c) 2012, 2013, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _REPRRD_H_
#define _REPRRD_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* constants */
#ifndef FALSE
# define FALSE			0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE			1
#endif /* ! TRUE */

/* status codes */
#define	REPRRD_STAT_UNKNOWN	(-1)	/* unknown status */
#define	REPRRD_STAT_OK		0	/* successful completion */
#define	REPRRD_STAT_INTERNAL	1	/* internal error */
#define	REPRRD_STAT_QUERY	2	/* query failure */
#define	REPRRD_STAT_NODATA	3	/* no data for specified domain */

typedef int REPRRD_STAT;

/* constants */
#define	REPRRD_TYPE_UNKNOWN	(-1)
#define	REPRRD_TYPE_MESSAGES	0
#define	REPRRD_TYPE_SPAM	1
#define	REPRRD_TYPE_LIMIT	2

#define	REPRRD_BACKSTEPS	2
#define	REPRRD_CF_AVERAGE	"AVERAGE"
#define	REPRRD_CF_FAILURES	"FAILURES"
#define	REPRRD_CF_HWPREDICT	"HWPREDICT"
#define	REPRRD_DEFHASHDEPTH	2
#define	REPRRD_STEP		3600

/* other types */
struct reprrd_handle;
typedef struct reprrd_handle * REPRRD;

/* prototypes */
extern void reprrd_close(REPRRD);
extern REPRRD reprrd_init(const char *, int);
extern REPRRD_STAT reprrd_query(REPRRD, const char *, int, int *,
                                char *, size_t);

#endif /* ! _REPRRD_H_ */
