/*
**  Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _DKIM_REPORT_H_
#define _DKIM_REPORT_H_

/* system includes */
#include <sys/types.h>
#include <sys/time.h>

/* libopendkim includes */
#include "dkim.h"

/* definitions */
#define	DKIM_REPORT_PREFIX	"_report._domainkey"

/* prototypes */
extern DKIM_STAT dkim_repinfo __P((DKIM *, DKIM_SIGINFO *,
                                   struct timeval *, unsigned char *, size_t));

#endif /* ! _DKIM_REPORT_H_ */
