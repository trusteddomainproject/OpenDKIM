/*
**  Copyright (c) 2009, 2012, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _AR_STRL_H_
#define _AR_STRL_H_

/* system includes */
#include <sys/types.h>

/* OpenDKIM includes */
#include <build-config.h>

/* prototypes */
#if HAVE_STRLCAT == 0
# define strlcat(x,y,z)	ar_strlcat((x), (y), (z))
extern size_t ar_strlcat __P((char *, const char *, ssize_t));
#endif /* HAVE_STRLCAT == 0 */

#if HAVE_STRLCPY == 0
# define strlcpy(x,y,z)	ar_strlcpy((x), (y), (z))
extern size_t ar_strlcpy __P((char *, const char *, ssize_t));
#endif /* HAVE_STRLCPY == 0 */

#endif /* _AR_STRL_H_ */
