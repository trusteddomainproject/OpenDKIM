/*
**  Copyright (c) 2004, 2005, 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: util.h,v 1.10 2010/05/22 06:05:45 cm-msk Exp $
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#ifndef lint
static char util_h_id[] = "@(#)$Id: util.h,v 1.10 2010/05/22 06:05:45 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdio.h>

/* opendkim includes */
#include "build-config.h"
#include "opendkim-db.h"

/* TYPES */
struct dkimf_dstring;

#ifdef _FFR_REPLACE_RULES
/*
**  REPLACE -- replacement table
*/

struct replace
{
	regex_t		repl_re;
	char *		repl_txt;
	struct replace	*repl_next;
};
#endif /* _FFR_REPLACE_RULES */

/* PROTOTYPES */
extern void dkimf_base64_encode_file __P((int, FILE *, int, int, int));
extern bool dkimf_checkhost __P((DKIMF_DB, char *));
extern bool dkimf_checkip __P((DKIMF_DB, struct sockaddr *));
#ifdef POPAUTH
extern bool dkimf_checkpopauth __P((DKIMF_DB, struct sockaddr *));
#endif /* POPAUTH */
extern bool dkimf_hostlist __P((char *, char **));
extern size_t dkimf_inet_ntoa __P((struct in_addr, char *, size_t));
#ifdef POPAUTH
extern int dkimf_initpopauth __P((void));
#endif /* POPAUTH */
#ifdef _FFR_REPLACE_RULES
extern void dkimf_free_replist __P((struct replace *));
extern bool dkimf_load_replist __P((FILE *, struct replace **));
#endif /* _FFR_REPLACE_RULES */
extern void dkimf_ipstring __P((char *, size_t, struct sockaddr_storage *));
extern bool dkimf_isblank __P((char *));
extern void dkimf_lowercase __P((u_char *));
extern void dkimf_mkpath __P((char *, size_t, char *, char *));
extern bool dkimf_mkregexp __P((char *, char *, size_t));
extern void dkimf_optlist __P((FILE *));
extern void dkimf_setmaxfd __P((void));
extern int dkimf_socket_cleanup __P((char *));
extern void dkimf_stripbrackets __P((char *));
extern void dkimf_stripcr __P((char *));
extern bool dkimf_subdomain __P((char *d1, char *d2));
extern void dkimf_trimspaces __P((u_char *));

extern struct dkimf_dstring *dkimf_dstring_new __P((int, int));
extern void dkimf_dstring_free __P((struct dkimf_dstring *));
extern bool dkimf_dstring_copy __P((struct dkimf_dstring *, char *));
extern bool dkimf_dstring_cat __P((struct dkimf_dstring *, char *));
extern bool dkimf_dstring_cat1 __P((struct dkimf_dstring *, int));
extern void dkimf_dstring_chop __P((struct dkimf_dstring *, int));
extern char *dkimf_dstring_get __P((struct dkimf_dstring *));
extern int dkimf_dstring_len __P((struct dkimf_dstring *));
extern void dkimf_dstring_blank __P((struct dkimf_dstring *));

#endif /* _UTIL_H_ */
