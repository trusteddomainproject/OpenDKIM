/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2011, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.h,v 1.10.2.1 2010/10/27 21:43:09 cm-msk Exp $
*/

#ifndef _STATS_H_
#define _STATS_H_

#ifndef lint
static char stats_h_id[] = "@(#)$Id: stats.h,v 1.10.2.1 2010/10/27 21:43:09 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "opendkim.h"

#define DKIMS_VERSION		3

/* column numbers */
#define	DKIMS_MI_JOBID		0
#define	DKIMS_MI_REPORTER	1
#define	DKIMS_MI_FROMDOMAIN	2
#define	DKIMS_MI_IPADDR		3
#define	DKIMS_MI_MSGTIME	4
#define	DKIMS_MI_MSGLEN		5
#define	DKIMS_MI_SIGCOUNT	6
#define DKIMS_MI_ATPS		7
#define DKIMS_MI_MAX		7

#define	DKIMS_SI_DOMAIN		0
#define	DKIMS_SI_PASS		1
#define	DKIMS_SI_FAIL_BODY	2
#define	DKIMS_SI_SIGLENGTH	3
#define	DKIMS_SI_SIGERROR	4
#define	DKIMS_SI_DNSSEC		5
#define DKIMS_SI_MAX		5

/* PROTOTYPES */
extern void dkimf_stats_init __P((void));
extern int dkimf_stats_record __P((char *, u_char *, char *, char *, Header,
                                   DKIM *,
#ifdef _FFR_STATSEXT
                                   struct statsext *,
#endif /* _FFR_STATSEXT */
#ifdef _FFR_ATPS
                                   int,
#endif /* _FFR_ATPS */
                                   struct sockaddr *));

#endif /* _STATS_H_ */
