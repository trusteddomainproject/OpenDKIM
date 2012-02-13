/*
**  Copyright (c) 2012, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_REPORT_H_
#define _DKIM_REPORT_H_

#ifndef lint
static char dkim_report_h_id[] = "@(#)$Id: dkim-keys.h,v 1.2 2009/07/23 17:40:23 cm-msk Exp $";
#endif /* !lint */

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
