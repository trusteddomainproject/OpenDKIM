/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.h,v 1.8 2010/09/01 22:51:48 cm-msk Exp $
*/

#ifndef _STATS_H_
#define _STATS_H_

#ifndef lint
static char stats_h_id[] = "@(#)$Id: stats.h,v 1.8 2010/09/01 22:51:48 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "opendkim.h"

/* PROTOTYPES */
extern void dkimf_stats_init __P((void));
extern int dkimf_stats_record __P((char *, char *, char *, char *, Header,
                                   DKIM *, dkim_policy_t, _Bool, _Bool, u_int,
                                   struct sockaddr *));

#endif /* _STATS_H_ */
