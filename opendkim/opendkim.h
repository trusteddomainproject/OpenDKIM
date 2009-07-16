/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim.h,v 1.1 2009/07/16 20:59:11 cm-msk Exp $
*/

#ifndef _OPENDKIM_H_
#define _OPENDKIM_H_

#ifndef lint
static char opendkim_h_id[] = "@(#)$Id: opendkim.h,v 1.1 2009/07/16 20:59:11 cm-msk Exp $";
#endif /* !lint */

#define	DKIMF_PRODUCT	"OpenDKIM Filter"
#define	DKIMF_PRODUCTNS	"OpenDKIM-Filter"
#define	DKIMF_VERSION	"1.0.0"

/* libmilter */
#include <libmilter/mfapi.h>

/* libopendkim */
#include <dkim.h>

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

#define AUTHRESULTSHDR	"Authentication-Results"

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
**  PEER -- peer list, listing clients to ignore
*/

typedef struct Peer * Peer;
struct Peer
{
	bool		peer_neg;
	char *		peer_info;
	struct Peer *	peer_next;
};

/* externs */
extern bool dolog;
extern char *progname;

/* prototypes, exported for test.c */
extern sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
extern sfsistat mlfi_envfrom __P((SMFICTX *, char **));
#ifdef _FFR_BODYLENGTH_DB
extern sfsistat mlfi_envrcpt __P((SMFICTX *, char **));
#endif /* _FFR_BODYLENGTH_DB */
extern sfsistat mlfi_header __P((SMFICTX *, char *, char *));
extern sfsistat mlfi_eoh __P((SMFICTX *));
extern sfsistat mlfi_body __P((SMFICTX *, u_char *, size_t));
extern sfsistat mlfi_eom __P((SMFICTX *));
extern sfsistat mlfi_abort __P((SMFICTX *));
extern sfsistat mlfi_close __P((SMFICTX *));

extern DKIM *dkimf_getdkim __P((void *));

#endif /* _OPENDKIM_H_ */
