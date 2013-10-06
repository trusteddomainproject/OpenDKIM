/*
**  Copyright (c) 2011-2013, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _REPUTE_H_
#define _REPUTE_H_

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
#define	REPUTE_STAT_UNKNOWN	(-1)	/* unknown status */
#define	REPUTE_STAT_OK		0	/* successful completion */
#define	REPUTE_STAT_INTERNAL	1	/* internal error */
#define	REPUTE_STAT_PARSE	2	/* parse failure */
#define	REPUTE_STAT_QUERY	3	/* query failure */

#define	REPUTE_CACHE		86400	/* XXX -- make this configurable */

typedef int REPUTE_STAT;

/* constant strings */
#define	REPUTE_NAME_REPUTATION	"reputation"
#define	REPUTE_NAME_REPUTON	"reputon"

#define	REPUTE_URI_APPLICATION	"email-id"
#define	REPUTE_URI_SCHEME	"http"
#define	REPUTE_URI_TEMPLATE	"{scheme}://{service}/.well-known/repute-template"

#define	REPUTE_APPLICATION	"application"
#define	REPUTE_REPUTONS		"reputons"
#define	REPUTE_RATER		"rater"
#define	REPUTE_ASSERTION	"assertion"
#define	REPUTE_RATED		"rated"
#define	REPUTE_RATING		"rating"
#define	REPUTE_CONFIDENCE	"confidence"
#define	REPUTE_SAMPLE_SIZE	"sample-size"
#define	REPUTE_GENERATED	"generated"
#define	REPUTE_EXT_IDENTITY	"identity"
#define	REPUTE_EXT_RATE		"rate"

#define	REPUTE_APPLICATION_VAL	"email-id"
#define	REPUTE_ID_DKIM		"dkim"
#define	REPUTE_ASSERT_SPAM	"spam"

/* other types */
struct repute_handle;
typedef struct repute_handle * REPUTE;

/* prototypes */
extern void repute_close(REPUTE);
extern const char * repute_curlversion(REPUTE);
extern const char *repute_error(REPUTE);
extern void repute_init(void);
extern REPUTE repute_new(const char *, unsigned int);
extern REPUTE_STAT repute_query(REPUTE, const char *, float *,
                                float *, unsigned long *, unsigned long *,
                                time_t *);
extern void repute_set_timeout(long);
extern void repute_useragent(REPUTE, const char *);

#endif /* ! _REPUTE_H_ */
