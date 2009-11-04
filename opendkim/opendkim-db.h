/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**      All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-db.h,v 1.4 2009/11/04 18:41:48 cm-msk Exp $
*/

#ifndef _OPENDKIM_DB_H_
#define _OPENDKIM_DB_H_

#ifndef lint
static char opendkim_db_h_id[] = "@(#)$Id: opendkim-db.h,v 1.4 2009/11/04 18:41:48 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <pthread.h>

/* macros */
#define	DKIMF_DB_FLAG_READONLY	0x01
#define	DKIMF_DB_FLAG_ICASE	0x02
#define	DKIMF_DB_FLAG_MATCHBOTH	0x04
#define	DKIMF_DB_FLAG_VALLIST	0x08

#define	DKIMF_DB_TYPE_UNKNOWN	(-1)
#define	DKIMF_DB_TYPE_FILE	0
#define	DKIMF_DB_TYPE_REFILE	1
#define	DKIMF_DB_TYPE_CSL	2
#define DKIMF_DB_TYPE_BDB	3
#define DKIMF_DB_TYPE_DSN	4

/* types */
struct dkimf_db;
typedef struct dkimf_db * DKIMF_DB;

/* prototypes */
extern void dkimf_db_close __P((DKIMF_DB));
extern int dkimf_db_delete __P((DKIMF_DB, void *, size_t));
extern int dkimf_db_get __P((DKIMF_DB, void *, size_t,
                             void *, size_t *, bool *));
extern int dkimf_db_mkarray __P((DKIMF_DB, char ***));
extern int dkimf_db_open __P((DKIMF_DB *, char *, u_int flags,
                              pthread_mutex_t *));
extern int dkimf_db_put __P((DKIMF_DB, void *, size_t, void *, size_t));
extern int dkimf_db_strerror __P((DKIMF_DB, char *, size_t));
extern int dkimf_db_type __P((DKIMF_DB));
extern int dkimf_db_walk __P((DKIMF_DB, _Bool, void *, size_t *, void *,
                              size_t *));

#endif /* _OPENDKIM_DB_H_ */
