/*
**  Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char repute_h_id[] = "$Id$";
#endif /* ! lint */

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

typedef int REPUTE_STAT;

/* constant strings */
#define	REPUTE_NAME_REPUTATION	"reputation"
#define	REPUTE_NAME_REPUTON	"reputon"

#define	REPUTE_URI_APPLICATION	"email"
#define	REPUTE_URI_SCHEME	"http"
#define	REPUTE_URI_TEMPLATE	"http://%s/repute_template.txt"
#define	REPUTE_URI_DEFTEMPLATE	"{application}/{domain}/{assertion}"

#define	REPUTE_XML_CODE_UNKNOWN		(-1)
#define	REPUTE_XML_CODE_ASSERTION	0
#define	REPUTE_XML_CODE_EXTENSION	1
#define	REPUTE_XML_CODE_RATED		2
#define	REPUTE_XML_CODE_RATER		3
#define	REPUTE_XML_CODE_RATER_AUTH	4
#define	REPUTE_XML_CODE_RATING		5
#define	REPUTE_XML_CODE_SAMPLE_SIZE	6
#define	REPUTE_XML_CODE_UPDATED		7

#define	REPUTE_XML_ASSERTION	"assertion"
#define	REPUTE_XML_EXTENSION	"extension"
#define	REPUTE_XML_RATED	"rated"
#define	REPUTE_XML_RATER	"rater"
#define	REPUTE_XML_RATER_AUTH	"rater-authenticity"
#define	REPUTE_XML_RATING	"rating"
#define	REPUTE_XML_SAMPLE_SIZE	"sample-size"
#define	REPUTE_XML_UPDATED	"updated"

#define	REPUTE_ASSERT_SENDS_SPAM "sends-spam"

#define	REPUTE_EXT_ID_DKIM	"IDENTITY: DKIM"

/* other types */
struct repute_handle;
typedef struct repute_handle * REPUTE;

/* prototypes */
extern void repute_close(REPUTE);
extern void repute_init(void);
extern REPUTE repute_new(const char *);
extern REPUTE_STAT repute_query(REPUTE, const char *, float *,
                                float *, unsigned long *, time_t *);

#endif /* ! _REPUTE_H_ */
