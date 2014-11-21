/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2014, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _OPENDKIM_H_
#define _OPENDKIM_H_

#define	DKIMF_PRODUCT	"OpenDKIM Filter"
#define	DKIMF_PRODUCTNS	"OpenDKIM-Filter"

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libmilter */
#ifdef DKIMF_MILTER_PROTOTYPES
# include <libmilter/mfapi.h>
#endif /* DKIMF_MILTER_PROTOTYPES */

/* libopendkim */
#include "dkim.h"

#ifdef USE_LUA
# ifdef DKIMF_LUA_PROTOTYPES
/* LUA */
# include <lua.h>
# endif /* DKIMF_LUA_PROTOTYPES */
#endif /* USE_LUA */

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
#define	DEFCONFFILE	CONFIG_BASE "/opendkim.conf"
#define	DEFFLOWDATATTL	86400
#define	DEFINTERNAL	"csl:127.0.0.1,::1"
#define	DEFMAXHDRSZ	65536
#define	DEFMAXVERIFY	3
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
#define	NULLDOMAIN	"(invalid)"
#define	SUPERUSER	"root"
#define	UNKNOWN		"unknown"

#define	DB_DOMAINS	1
#define DB_THIRDPARTY	2
#define	DB_DONTSIGNTO	3
#define	DB_MTAS		4
#define	DB_MACROS	5
#define	DB_SIGNINGTABLE	6

#define AUTHRESULTSHDR	"Authentication-Results"
#define ORCPTHEADER	"Original-Recipient"

#define	SWHEADERNAME	"DKIM-Filter"
#define	SELECTCANONHDR	"Canonicalization"

#ifdef _FFR_VBR
# define VBRTYPEHEADER	"VBR-Type"
# define VBRCERTHEADER	"VBR-Certifiers"
#endif /* _FFR_VBR */

#ifdef _FFR_ADSP_LISTS
# define ADSP_DISCARDABLE_SMTP	"550"
# define ADSP_DISCARDABLE_ESC	"5.7.1"
# define ADSP_DISCARDABLE_TEXT	"ADSP discardable mail may not be sent to this address"
#endif /* _FFR_ADSP_LISTS */

/* POPAUTH db */
#if POPAUTH
# define POPAUTHDB	"/etc/mail/popip.db"
#endif /* POPAUTH */

/*
**  HEADER -- a handle referring to a header
*/

typedef struct Header * Header;
struct Header
{
	char *		hdr_hdr;
	char *		hdr_val;
	struct Header *	hdr_next;
	struct Header *	hdr_prev;
};

/*
**  SIGNREQ -- signing request (for multiple signature requests)
*/

typedef struct signreq * SIGNREQ;
struct signreq
{
	ssize_t			srq_signlen;
	void *			srq_keydata;
	u_char *		srq_domain;
	u_char *		srq_selector;
	u_char *		srq_signer;
	DKIM *			srq_dkim;
	struct signreq *	srq_next;
};

#ifdef _FFR_STATSEXT
/*
**  STATSEXT -- statistics extension data
*/

typedef struct statsext * statsext;
struct statsext
{
	char			se_name[BUFRSZ];
	char			se_value[BUFRSZ];
	struct statsext * 	se_next;
};
#endif /* _FFR_STATSEXT */

/* externs */
extern _Bool dolog;
extern char *progname;

/* prototypes, exported for test.c */
#ifdef DKIMF_MILTER_PROTOTYPES
extern sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
extern sfsistat mlfi_envfrom __P((SMFICTX *, char **));
extern sfsistat mlfi_envrcpt __P((SMFICTX *, char **));
extern sfsistat mlfi_header __P((SMFICTX *, char *, char *));
extern sfsistat mlfi_eoh __P((SMFICTX *));
extern sfsistat mlfi_body __P((SMFICTX *, u_char *, size_t));
extern sfsistat mlfi_eom __P((SMFICTX *));
extern sfsistat mlfi_abort __P((SMFICTX *));
extern sfsistat mlfi_close __P((SMFICTX *));
#endif /* DKIMF_MILTER_PROTOTYPES */

extern DKIM *dkimf_getdkim __P((void *));
extern struct signreq *dkimf_getsrlist __P((void *));

#ifdef USE_LDAP
extern char *dkimf_get_ldap_param __P((int));
#endif /* USE_LDAP */

#ifdef USE_LUA
# ifdef DKIMF_LUA_PROTOTYPES
extern void dkimf_import_globals __P((void *, lua_State *));
extern int dkimf_xs_addheader __P((lua_State *));
extern int dkimf_xs_addrcpt __P((lua_State *));
extern int dkimf_xs_bodylength __P((lua_State *));
extern int dkimf_xs_canonlength __P((lua_State *));
extern int dkimf_xs_clienthost __P((lua_State *));
extern int dkimf_xs_clientip __P((lua_State *));
extern int dkimf_xs_dbclose __P((lua_State *));
extern int dkimf_xs_dbhandle __P((lua_State *));
extern int dkimf_xs_dbopen __P((lua_State *));
extern int dkimf_xs_dbquery __P((lua_State *));
extern int dkimf_xs_delheader __P((lua_State *));
extern int dkimf_xs_delrcpt __P((lua_State *));
extern int dkimf_xs_export __P((lua_State *));
extern int dkimf_xs_fromdomain __P((lua_State *));
extern int dkimf_xs_getenvfrom __P((lua_State *));
extern int dkimf_xs_getheader __P((lua_State *));
extern int dkimf_xs_getreputation __P((lua_State *));
extern int dkimf_xs_getsigarray __P((lua_State *));
extern int dkimf_xs_getsigcount __P((lua_State *));
extern int dkimf_xs_getsigdomain __P((lua_State *));
extern int dkimf_xs_getsighandle __P((lua_State *));
extern int dkimf_xs_getsigidentity __P((lua_State *));
extern int dkimf_xs_getsymval __P((lua_State *));
extern int dkimf_xs_internalip __P((lua_State *));
extern int dkimf_xs_log __P((lua_State *));
extern int dkimf_xs_parsefield __P((lua_State *));
extern int dkimf_xs_popauth __P((lua_State *));
extern int dkimf_xs_quarantine __P((lua_State *));
extern int dkimf_xs_rblcheck __P((lua_State *));
extern int dkimf_xs_rcpt __P((lua_State *));
extern int dkimf_xs_rcptarray __P((lua_State *));
extern int dkimf_xs_rcptcount __P((lua_State *));
extern int dkimf_xs_replaceheader __P((lua_State *));
extern int dkimf_xs_resign __P((lua_State *));
extern int dkimf_xs_requestsig __P((lua_State *));
extern int dkimf_xs_setpartial __P((lua_State *));
extern int dkimf_xs_setreply __P((lua_State *));
extern int dkimf_xs_setresult __P((lua_State *));
extern int dkimf_xs_sigbhresult __P((lua_State *));
extern int dkimf_xs_sigignore __P((lua_State *));
extern int dkimf_xs_signfor __P((lua_State *));
extern int dkimf_xs_sigresult __P((lua_State *));
#  ifdef _FFR_REPUTATION
extern int dkimf_xs_spam __P((lua_State *));
#  endif /* _FFR_REPUTATION */
#  ifdef _FFR_STATSEXT
extern int dkimf_xs_statsext __P((lua_State *));
#  endif /* _FFR_STATSEXT */
extern int dkimf_xs_verify __P((lua_State *));
extern int dkimf_xs_xtag __P((lua_State *));
# endif /* DKIMF_LUA_PROTOTYPES */
#endif /* USE_LUA */

#endif /* _OPENDKIM_H_ */
