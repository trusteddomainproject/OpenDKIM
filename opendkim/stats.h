/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.h,v 1.9 2010/09/14 18:23:39 cm-msk Exp $
*/

#ifndef _STATS_H_
#define _STATS_H_

#ifndef lint
static char stats_h_id[] = "@(#)$Id: stats.h,v 1.9 2010/09/14 18:23:39 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "opendkim.h"

/* column numbers */
#define	DKIMS_MI_JOBID		0
#define	DKIMS_MI_REPORTER	1
#define	DKIMS_MI_FROMDOMAIN	2
#define	DKIMS_MI_IPADDR		3
#define	DKIMS_MI_ANONYMIZED	4
#define	DKIMS_MI_MSGTIME	5
#define	DKIMS_MI_MSGLEN		6
#define	DKIMS_MI_SIGCOUNT	7
#define DKIMS_MI_ADSP_FOUND	8
#define DKIMS_MI_ADSP_UNKNOWN	9
#define DKIMS_MI_ADSP_ALL	10
#define DKIMS_MI_ADSP_DISCARD	11
#define DKIMS_MI_ADSP_FAIL	12
#define DKIMS_MI_MAILINGLIST	13
#define DKIMS_MI_RECEIVEDCNT	14
#define DKIMS_MI_CONTENTTYPE	15
#define DKIMS_MI_CONTENTENCODING 16
#define DKIMS_MI_MAX		16

#define	DKIMS_SI_DOMAIN		0
#define	DKIMS_SI_ALGORITHM	1
#define	DKIMS_SI_HEADER_CANON	2
#define	DKIMS_SI_BODY_CANON	3
#define	DKIMS_SI_IGNORE		4
#define	DKIMS_SI_PASS		5
#define	DKIMS_SI_FAIL_BODY	6
#define	DKIMS_SI_SIGLENGTH	7
#define	DKIMS_SI_KEY_T		8
#define	DKIMS_SI_KEY_G		9
#define	DKIMS_SI_KEY_G_NAME	10
#define	DKIMS_SI_KEY_DK_COMPAT	11
#define	DKIMS_SI_SIGERROR	12
#define	DKIMS_SI_SIG_T		13
#define	DKIMS_SI_SIG_X		14
#define	DKIMS_SI_SIG_Z		15
#define	DKIMS_SI_DNSSEC		16
#define	DKIMS_SI_SIGNED_FIELDS	17
#define	DKIMS_SI_CHANGED_FIELDS	18
#define DKIMS_SI_MAX		18

/* PROTOTYPES */
extern void dkimf_stats_init __P((void));
extern int dkimf_stats_record __P((char *, char *, char *, char *, Header,
                                   DKIM *, dkim_policy_t, _Bool, _Bool, u_int,
#ifdef _FFR_STATSEXT
                                   struct statsext *,
#endif /* _FFR_STATSEXT */
                                   struct sockaddr *));

#endif /* _STATS_H_ */
