/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _RFC2822_H_
#define _RFC2822_H_

#ifndef lint
static char rfc2822_h_id[] = "@(#)$Id: rfc2822.h,v 1.1 2009/07/16 19:12:04 cm-msk Exp $";
#endif /* !lint */

/* prototypes */
extern int rfc2822_mailbox_split __P((char *line, char **user_out,
                                      char **domain_out));

#endif /* ! _RFC2822_H_ */
