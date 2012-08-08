/*
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _STRL_H_
#define _STRL_H_

/* system includes */
#include <sys/types.h>

/* prototypes */
extern size_t strlcat(register char *, register const char *, ssize_t);
extern size_t strlcpy(register char *, register const char *, ssize_t);

#endif /* _STRL_H_ */
