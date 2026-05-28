/*
**  Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _FLOWRATE_H_
#define _FLOWRATE_H_

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* opendkim includes */
#include "opendkim-db.h"


/* prototypes */
extern int dkimf_rate_check (const char *, DKIMF_DB, DKIMF_DB, int, int,
                                 unsigned int *);

#endif /* _FLOWRATE_H_ */
