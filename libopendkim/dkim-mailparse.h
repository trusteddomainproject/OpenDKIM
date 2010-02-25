/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_MAILPARSE_H_
#define _DKIM_MAILPARSE_H_

#ifndef lint
static char dkim_mailparse_h_id[] = "@(#)$Id: dkim-mailparse.h,v 1.2 2010/02/25 21:52:06 cm-msk Exp $";
#endif /* !lint */

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
extern int dkim_mail_parse __P((char *line, char **user_out,
                                char **domain_out));

#endif /* ! _DKIM_MAILPARSE_H_ */
