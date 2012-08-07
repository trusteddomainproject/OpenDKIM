/*
**  Copyright (c) 2005 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _BASE64_H_
#define _BASE64_H_

/* system includes */
#include <sys/types.h>

/* prototypes */
extern int dkim_base64_decode(u_char *str, u_char *buf, size_t buflen);
extern int dkim_base64_encode(u_char *data, size_t datalen, u_char *buf,
                              size_t buflen);

#endif /* ! _BASE64_H_ */
