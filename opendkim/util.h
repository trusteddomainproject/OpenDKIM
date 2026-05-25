/*
**  Copyright (c) 2004, 2005, 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.
**    All rights reserved.
**
*/

#ifndef _UTIL_H_
#define _UTIL_H_

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
extern void dkimf_base64_encode_file (int, FILE *, int, int, int);
extern _Bool dkimf_checkhost (DKIMF_DB, char *);
extern _Bool dkimf_checkip (DKIMF_DB, struct sockaddr *);
#ifdef POPAUTH
extern _Bool dkimf_checkpopauth (DKIMF_DB, struct sockaddr *);
#endif /* POPAUTH */
extern _Bool dkimf_hostlist (char *, char **);
extern size_t dkimf_inet_ntoa (struct in_addr, char *, size_t);
#ifdef POPAUTH
extern int dkimf_initpopauth (void);
#endif /* POPAUTH */
#ifdef _FFR_REPLACE_RULES
extern void dkimf_free_replist (struct replace *);
extern _Bool dkimf_load_replist (FILE *, struct replace **);
#endif /* _FFR_REPLACE_RULES */
extern void dkimf_ipstring (char *, size_t, struct sockaddr_storage *);
extern _Bool dkimf_isblank (char *);
extern void dkimf_lowercase (u_char *);
extern void dkimf_mkpath (char *, size_t, char *, char *);
extern _Bool dkimf_mkregexp (char *, char *, size_t);
extern void dkimf_optlist (FILE *);
extern void dkimf_setmaxfd (void);
extern int dkimf_socket_cleanup (char *);
extern void dkimf_stripbrackets (char *);
extern void dkimf_stripcr (char *);
extern _Bool dkimf_subdomain (char *d1, char *d2);
extern void dkimf_trimspaces (u_char *);

extern struct dkimf_dstring *dkimf_dstring_new (int, int);
extern void dkimf_dstring_free (struct dkimf_dstring *);
extern _Bool dkimf_dstring_copy (struct dkimf_dstring *, u_char *);
extern _Bool dkimf_dstring_cat (struct dkimf_dstring *, u_char *);
extern _Bool dkimf_dstring_cat1 (struct dkimf_dstring *, int);
extern _Bool dkimf_dstring_catn (struct dkimf_dstring *, u_char *, size_t);
extern void dkimf_dstring_chop (struct dkimf_dstring *, int);
extern u_char *dkimf_dstring_get (struct dkimf_dstring *);
extern int dkimf_dstring_len (struct dkimf_dstring *);
extern void dkimf_dstring_blank (struct dkimf_dstring *);
extern size_t dkimf_dstring_printf (struct dkimf_dstring *, char *, ...);

#ifdef USE_UNBOUND
extern _Bool dkimf_timespec_past (struct timespec *tv);
extern int dkimf_wait_fd (int fd, struct timespec *until);
#endif /* USE_UNBOUND */

#endif /* _UTIL_H_ */
