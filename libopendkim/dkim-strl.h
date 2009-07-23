/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_STRL_H_
#define _DKIM_STRL_H_

#ifndef lint
static char dkim_strl_h_id[] = "@(#)$Id: dkim-strl.h,v 1.1 2009/07/23 17:54:22 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

/* OpenDKIM includes */
#include <build-config.h>

/* prototypes */
#if HAVE_STRLCAT == 0
# define strlcat(x,y,z)	dkim_strlcat((x), (y), (z))
extern size_t dkim_strlcat __P((char *, const char *, ssize_t));
#endif /* HAVE_STRLCAT == 0 */

#if HAVE_STRLCPY == 0
# define strlcpy(x,y,z)	dkim_strlcpy((x), (y), (z))
extern size_t dkim_strlcpy __P((char *, const char *, ssize_t));
#endif /* HAVE_STRLCPY == 0 */

#endif /* _DKIM_STRL_H_ */
