/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, 2014, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _DKIM_MAILPARSE_H_
#define _DKIM_MAILPARSE_H_


/* prototypes */
extern int dkim_mail_parse (unsigned char *line, unsigned char **user_out,
                                unsigned char **domain_out);
extern int dkim_mail_parse_multi (unsigned char *line,
                                      unsigned char ***users_out,
                                      unsigned char ***domains_out);
#endif /* ! _DKIM_MAILPARSE_H_ */
