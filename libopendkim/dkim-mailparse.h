/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _DKIM_MAILPARSE_H_
#define _DKIM_MAILPARSE_H_

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* prototypes */
extern int dkim_mail_parse __P((unsigned char *line, unsigned char **user_out,
                                unsigned char **domain_out));

#endif /* ! _DKIM_MAILPARSE_H_ */
