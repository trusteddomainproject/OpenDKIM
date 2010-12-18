/*
**  Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _BASE32_H_
#define _BASE32_H_

#ifndef lint
static char base32_h_id[] = "@(#)$Id$";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

/*
**  BASE32_ENCODE -- encode a string using base32
**
**  Parameters:
**  	buf -- destination buffer
**  	buflen -- bytes available at buf (updated)
**  	data -- pointer to data to encode
**  	size -- bytes at "data" to encode
**
**  Return value:
**  	Length of encoding.
**
**  Notes:
**  	buf should be at least a byte more than *buflen to hold the trailing
**  	'\0'.
**
**  	*buflen is updated to count the number of bytes read from "data".
*/

extern int base32_encode __P((char *, size_t *, const void *, size_t));

#endif /* ! _BASE32_H_ */
