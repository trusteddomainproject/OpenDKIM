/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_MAILPARSE_H_
#define _DKIM_MAILPARSE_H_

#ifndef lint
static char dkim_mailparse_h_id[] = "@(#)$Id: dkim-mailparse.h,v 1.1 2009/11/05 20:36:16 cm-msk Exp $";
#endif /* !lint */

/* prototypes */
extern int dkim_mail_parse __P((char *line, char **user_out,
                                char **domain_out));

#endif /* ! _DKIM_MAILPARSE_H_ */
