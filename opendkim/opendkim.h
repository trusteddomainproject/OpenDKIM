/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim.h,v 1.13.2.25 2009/11/28 06:22:52 cm-msk Exp $
*/

#ifndef _OPENDKIM_H_
#define _OPENDKIM_H_

#ifndef lint
static char opendkim_h_id[] = "@(#)$Id: opendkim.h,v 1.13.2.25 2009/11/28 06:22:52 cm-msk Exp $";
#endif /* !lint */

#define	DKIMF_PRODUCT	"OpenDKIM Filter"
#define	DKIMF_PRODUCTNS	"OpenDKIM-Filter"
#define	DKIMF_VERSION	"1.2.0.dev"

/* system includes */
#include <sys/types.h>
#include <stdbool.h>

/* libmilter */
#include <libmilter/mfapi.h>

/* libopendkim */
#include <dkim.h>

#ifdef _FFR_LUA
/* LUA */
# include <lua.h>
#endif /* _FFR_LUA */

/* make sure we have TRUE and FALSE */
#ifndef FALSE
# define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* !TRUE */

/* defaults, limits, etc. */
#define	BUFRSZ		1024
#define	CACHESTATSINT	300
#define	CBINTERVAL	3
#define CMDLINEOPTS	"a:Ab:c:C:d:DfF:hi:I:k:KlL:m:M:no:p:P:qrRs:S:t:T:u:U:vVWx:?"
#define	DEFINTERNAL	"csl:127.0.0.1"
#define	DEFMAXHDRSZ	65536
#define	DEFTIMEOUT	5
#define	HOSTUNKNOWN	"unknown-host"
#define	JOBIDUNKNOWN	"(unknown-jobid)"
#define	LOCALHOST	"127.0.0.1"
#define	MAXADDRESS	256
#define	MAXARGV		65536
#define	MAXBUFRSZ	65536
#define	MAXHDRCNT	64
#define	MAXHDRLEN	78
#define	MAXSIGNATURE	1024
#define	MTAMARGIN	78
#define	TEMPFILE	"/var/tmp/dkimXXXXXX"
#define	UNKNOWN		"unknown"

#define	DB_DOMAINS	1
#define DB_THIRDPARTY	2
#define	DB_DONTSIGNTO	3
#define	DB_MTAS		4
#define	DB_MACROS	5

#define AUTHRESULTSHDR	"Authentication-Results"
#define ORCPTHEADER	"X-Original-Recipient"

#define	XHEADERNAME	"X-DKIM"
#define	XSELECTCANONHDR	"X-Canonicalization"

#ifdef _FFR_VBR
# define XVBRTYPEHEADER	"X-VBR-Type"
# define XVBRCERTHEADER	"X-VBR-Certifiers"
#endif /* _FFR_VBR */

/* POPAUTH db */
#if POPAUTH
# define POPAUTHDB	"/etc/mail/popip.db"
#endif /* POPAUTH */

/*
**  SIGNREQ -- signing request (for multiple signature requests)
*/

typedef struct signreq * SIGNREQ;
struct signreq
{
	struct keytable	*	srq_key;
	DKIM *			srq_dkim;
	struct signreq *	srq_next;
};

/* externs */
extern _Bool dolog;
extern char *progname;

/* prototypes, exported for test.c */
extern sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
extern sfsistat mlfi_envfrom __P((SMFICTX *, char **));
extern sfsistat mlfi_envrcpt __P((SMFICTX *, char **));
extern sfsistat mlfi_header __P((SMFICTX *, char *, char *));
extern sfsistat mlfi_eoh __P((SMFICTX *));
extern sfsistat mlfi_body __P((SMFICTX *, u_char *, size_t));
extern sfsistat mlfi_eom __P((SMFICTX *));
extern sfsistat mlfi_abort __P((SMFICTX *));
extern sfsistat mlfi_close __P((SMFICTX *));

extern DKIM *dkimf_getdkim __P((void *));
extern struct signreq *dkimf_getsrlist __P((void *));

#ifdef _FFR_LUA
extern int dkimf_xs_addrcpt __P((lua_State *));
extern int dkimf_xs_bodylength __P((lua_State *));
extern int dkimf_xs_canonlength __P((lua_State *));
extern int dkimf_xs_clienthost __P((lua_State *));
extern int dkimf_xs_dbhandle __P((lua_State *));
extern int dkimf_xs_dbquery __P((lua_State *));
extern int dkimf_xs_delrcpt __P((lua_State *));
extern int dkimf_xs_fromdomain __P((lua_State *));
extern int dkimf_xs_getheader __P((lua_State *));
extern int dkimf_xs_getpolicy __P((lua_State *));
extern int dkimf_xs_getpresult __P((lua_State *));
extern int dkimf_xs_getsigcount __P((lua_State *));
extern int dkimf_xs_getsigdomain __P((lua_State *));
extern int dkimf_xs_getsighandle __P((lua_State *));
extern int dkimf_xs_getsigidentity __P((lua_State *));
extern int dkimf_xs_getsymval __P((lua_State *));
extern int dkimf_xs_internalip __P((lua_State *));
extern int dkimf_xs_popauth __P((lua_State *));
extern int dkimf_xs_rcpt __P((lua_State *));
extern int dkimf_xs_rcptcount __P((lua_State *));
extern int dkimf_xs_resign __P((lua_State *));
extern int dkimf_xs_requestsig __P((lua_State *));
extern int dkimf_xs_setpartial __P((lua_State *));
extern int dkimf_xs_setreply __P((lua_State *));
extern int dkimf_xs_sigbhresult __P((lua_State *));
extern int dkimf_xs_sigignore __P((lua_State *));
extern int dkimf_xs_sigresult __P((lua_State *));
extern int dkimf_xs_verify __P((lua_State *));
#endif /* _FFR_LUA */

#endif /* _OPENDKIM_H_ */
