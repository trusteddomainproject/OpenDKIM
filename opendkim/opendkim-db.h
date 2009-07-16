/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**      All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-db.h,v 1.1 2009/07/16 20:59:11 cm-msk Exp $
*/

#ifndef _OPENDKIM_DB_H_
#define _OPENDKIM_DB_H_

#ifndef lint
static char opendkim_db_h_id[] = "@(#)$Id: opendkim-db.h,v 1.1 2009/07/16 20:59:11 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <pthread.h>

/* libdb includes */
#include <db.h>

/* opendkim includes */
#include "opendkim.h"

#ifndef DB_NOTFOUND
# define DB_NOTFOUND    1
#endif /* ! DB_NOTFOUND */
#ifndef DB_VERSION_MAJOR
# define DB_VERSION_MAJOR   1
#endif /* ! DB_VERSION_MAJOR */

#define DB_VERSION_CHECK(x,y,z) ((DB_VERSION_MAJOR == (x) && \
				  DB_VERSION_MINOR == (y) && \
				  DB_VERSION_PATCH >= (z)) || \
				 (DB_VERSION_MAJOR == (x) && \
				  DB_VERSION_MINOR > (y)) || \
				 DB_VERSION_MAJOR > (x))

#if DB_VERSION_CHECK(3,0,0)
# define DB_STRERROR(x)		db_strerror(x)
#else /* DB_VERSION_CHECK(3,0,0) */
# define DB_STRERROR(x)		strerror(errno)
#endif /* DB_VERSION_CHECK(3,0,0) */

#if DB_VERSION_MAJOR < 2
# define DKIMF_DBCLOSE(db)	(db)->close((db))
#else /* DB_VERSION_MAJOR < 2 */
# define DKIMF_DBCLOSE(db)	(db)->close((db), 0)
#endif /* DB_VERSION_MAJOR < 2 */

/* PROTOTYPES */
extern int dkimf_db_delete __P((DB *, char *, pthread_mutex_t *));
extern int dkimf_db_get __P((DB *, char *, void *, size_t *, bool *,
                             pthread_mutex_t *));
extern int dkimf_db_open_ro __P((DB **, const char *));
extern int dkimf_db_open_rw __P((DB **, const char *));
extern int dkimf_db_put __P((DB *, char *, void *, size_t,
                             pthread_mutex_t *));

#endif /* _OPENDKIM_DB_H_ */
