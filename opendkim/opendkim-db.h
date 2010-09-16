/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**      All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-db.h,v 1.15 2010/09/16 04:47:39 cm-msk Exp $
*/

#ifndef _OPENDKIM_DB_H_
#define _OPENDKIM_DB_H_

#ifndef lint
static char opendkim_db_h_id[] = "@(#)$Id: opendkim-db.h,v 1.15 2010/09/16 04:47:39 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <pthread.h>

/* macros */
#define	DKIMF_DB_FLAG_READONLY	0x01
#define	DKIMF_DB_FLAG_ICASE	0x02
#define	DKIMF_DB_FLAG_MATCHBOTH	0x04
#define	DKIMF_DB_FLAG_VALLIST	0x08
#define	DKIMF_DB_FLAG_USETLS	0x10
#define	DKIMF_DB_FLAG_MAKELOCK	0x20

#define	DKIMF_DB_TYPE_UNKNOWN	(-1)
#define	DKIMF_DB_TYPE_FILE	0
#define	DKIMF_DB_TYPE_REFILE	1
#define	DKIMF_DB_TYPE_CSL	2
#define DKIMF_DB_TYPE_BDB	3
#define DKIMF_DB_TYPE_DSN	4
#define DKIMF_DB_TYPE_LDAP	5
#define DKIMF_DB_TYPE_LUA	6

#define	DKIMF_LDAP_PARAM_BINDUSER	0
#define	DKIMF_LDAP_PARAM_BINDPW		1
#define	DKIMF_LDAP_PARAM_AUTHMECH	2
#define	DKIMF_LDAP_PARAM_USETLS		3
#define	DKIMF_LDAP_PARAM_AUTHREALM	4
#define	DKIMF_LDAP_PARAM_AUTHUSER	5
#define	DKIMF_LDAP_PARAM_AUTHNAME	6

#define DKIMF_LDAP_PARAM_MAX		6

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* types */
struct dkimf_db;
typedef struct dkimf_db * DKIMF_DB;

struct dkimf_db_data
{
	unsigned int	dbdata_flags;
	char *		dbdata_buffer;
	size_t		dbdata_buflen;
};
typedef struct dkimf_db_data * DKIMF_DBDATA;

#define	DKIMF_DB_DATA_BINARY	0x01		/* data is binary */

/* prototypes */
extern int dkimf_db_close __P((DKIMF_DB));
extern int dkimf_db_delete __P((DKIMF_DB, void *, size_t));
extern int dkimf_db_fd __P((DKIMF_DB));
extern int dkimf_db_get __P((DKIMF_DB, void *, size_t,
                             DKIMF_DBDATA, unsigned int, _Bool *));
extern int dkimf_db_mkarray __P((DKIMF_DB, char ***));
extern int dkimf_db_open __P((DKIMF_DB *, char *, u_int flags,
                              pthread_mutex_t *, char **));
extern int dkimf_db_put __P((DKIMF_DB, void *, size_t, void *, size_t));
extern int dkimf_db_rewalk __P((DKIMF_DB, char *, DKIMF_DBDATA, unsigned int,
                                void **));
extern void dkimf_db_set_ldap_param __P((int, char *));
extern int dkimf_db_strerror __P((DKIMF_DB, char *, size_t));
extern int dkimf_db_type __P((DKIMF_DB));
extern int dkimf_db_walk __P((DKIMF_DB, _Bool, void *, size_t *,
                              DKIMF_DBDATA, unsigned int));

#endif /* _OPENDKIM_DB_H_ */
