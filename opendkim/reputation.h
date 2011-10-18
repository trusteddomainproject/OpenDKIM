/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
**
**  $Id: reputation.h,v 1.10.2.1 2010/10/27 21:43:09 cm-msk Exp $
*/

#ifndef _REPUTATION_H_
#define _REPUTATION_H_

#ifndef lint
static char reputaton_h_id[] = "@(#)$Id: stats.h,v 1.10.2.1 2010/10/27 21:43:09 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* opendkim includes */
#include "opendkim.h"
#include "opendkim-db.h"

/* definitions */
#define	DKIMF_REP_DEFFACTOR	1

/* data types */
struct reputation;
typedef struct reputation * DKIMF_REP;

/* PROTOTYPES */
extern int dkimf_rep_init __P((DKIMF_REP *, time_t, DKIMF_DB, DKIMF_DB,
                               DKIMF_DB));
extern int dkimf_rep_check __P((DKIMF_REP, DKIM_SIGINFO *, _Bool,
                                void *, size_t));
extern void dkimf_rep_close __P((DKIMF_REP));

#endif /* _REPUTATION_H_ */
