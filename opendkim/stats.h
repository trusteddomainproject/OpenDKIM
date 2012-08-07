/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _STATS_H_
#define _STATS_H_

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
#define DKIMS_MI_SPAM		8
#define DKIMS_MI_MAX		8

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
                                   int, int, struct sockaddr *));

#endif /* _STATS_H_ */
