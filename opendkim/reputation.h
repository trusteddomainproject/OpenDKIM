/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _REPUTATION_H_
#define _REPUTATION_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* opendkim includes */
#include "opendkim.h"
#include "opendkim-db.h"

/* definitions */
#define	DKIMF_REP_DEFCACHETTL	3600
#define	DKIMF_REP_DEFFACTOR	1

/* data types */
struct reputation;
typedef struct reputation * DKIMF_REP;

/* PROTOTYPES */
extern int dkimf_rep_init __P((DKIMF_REP *, time_t, unsigned int, unsigned int,
                               char *, char *, DKIMF_DB, DKIMF_DB, DKIMF_DB,
                               DKIMF_DB));
extern int dkimf_rep_check __P((DKIMF_REP, DKIM_SIGINFO *, _Bool,
                                void *, size_t, unsigned long *, float *,
                                unsigned long *, unsigned long *,
                                char *, size_t));
extern int dkimf_rep_chown_cache __P((DKIMF_REP, uid_t));
extern void dkimf_rep_close __P((DKIMF_REP));

#endif /* _REPUTATION_H_ */
