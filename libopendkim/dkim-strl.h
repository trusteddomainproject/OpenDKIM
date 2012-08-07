/*
**  Copyright (c) 2009, 2012, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_STRL_H_
#define _DKIM_STRL_H_

/* system includes */
#include <sys/types.h>

/* OpenDKIM includes */
#include "build-config.h"

/* mappings */
#if HAVE_STRLCAT == 0
# define strlcat(x,y,z)	dkim_strlcat((x), (y), (z))
#endif /* HAVE_STRLCAT == 0 */

#if HAVE_STRLCPY == 0
# define strlcpy(x,y,z)	dkim_strlcpy((x), (y), (z))
#endif /* HAVE_STRLCPY == 0 */

#endif /* _DKIM_STRL_H_ */
