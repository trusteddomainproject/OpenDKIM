/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-db.c,v 1.3 2009/07/21 23:36:39 cm-msk Exp $
*/

#ifndef lint
static char opendkim_db_c_id[] = "@(#)$Id: opendkim-db.c,v 1.3 2009/07/21 23:36:39 cm-msk Exp $";
#endif /* !lint */

#ifdef USE_DB

/* system includes */
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

/* opendkim includes */
#include "opendkim-db.h"

#define DB_MODE	0644

/*
**  DKIMF_DB_OPEN -- wrapper for opening BerkDB files
**
**  Parameters:
**  	db -- Pointer to the db pointer to open
**  	file -- filename to open
**	ro -- read-only (boolean)
**
**  Return value:
**  	0 -- success
**   	!0 -- errno or status (depends on DB version)
**
**  Side effects:
**  	*db will be set to an open file handle on success
*/

static int
dkimf_db_open(DB **db, const char *file, _Bool ro)
{
#if DB_VERSION_CHECK(2,0,0)
	int flags = 0;
#endif /* DB_VERSION_CHECK(2,0,0) */
	int status = 0;
	DBTYPE dbtype;

	assert(db != NULL);
	assert(file != NULL);

#if DB_VERSION_CHECK(2,0,0)
	if (ro)
	{
		flags |= DB_RDONLY;
		dbtype = DB_UNKNOWN;
	}
	else
	{
		flags |= DB_CREATE;
		dbtype = DB_HASH;
	}
#else /* DB_VERSION_CHECK(2,0,0) */
	dbtype = DB_HASH;
#endif /* DB_VERSION_CHECK(2,0,0) */

#if DB_VERSION_CHECK(3,0,0)
	status = db_create(db, NULL, 0);
	if (status == 0)
	{
# if DB_VERSION_CHECK(4,1,25)
		status = (*db)->open((*db), NULL, file, NULL, dbtype,
		                     flags, 0);
# else /* DB_VERSION_CHECK(4,1,25) */
		status = (*db)->open((*db), file, NULL, dbtype, flags, 0);
# endif /* DB_VERSION_CHECK(4,1,25) */
	}
#elif DB_VERSION_CHECK(2,0,0)
	status = db_open(file, dbtype, flags, DB_MODE, NULL, NULL, db);
#else /* DB_VERSION_MAJOR < 2 */
	*db = dbopen(file, (ro ? O_RDONLY :(O_CREAT|O_RDWR)), DB_MODE,
	             dbtype, NULL);
	if (*db == NULL)
		status = errno;
#endif /* DB_VERSION_CHECK */

	return status;
}

/*
**  DKIMF_DB_OPEN_RO -- wrapper for opening Sleepycat database files read-only
**
**  Parameters:
**  	db -- Pointer to the db pointer to open
**  	file -- filename to open
**
**  Return value:
**  	0 -- success
**   	!0 -- errno or status (depends on DB version)
**
**  Side effects:
**  	*db will be set to an open file handle on success
*/

int
dkimf_db_open_ro(DB **db, const char *file)
{
	assert(db != NULL);
	assert(file != NULL);

	return dkimf_db_open(db, file, TRUE);
}

/*
**  DKIMF_DB_OPEN_RW -- wrapper for opening Sleepycat database files read-write
**
**  Parameters:
**  	db -- Pointer to the db pointer to open
**  	file -- filename to open
**
**  Return value:
**  	0 -- success
**   	!0 -- errno or status (depends on DB version)
**
**  Side effects:
**  	*db will be set to an open file handle on success
*/

int
dkimf_db_open_rw(DB **db, const char *file)
{
	assert(db != NULL);
	assert(file != NULL);

	return dkimf_db_open(db, file, FALSE);
}

/*
**  DKIMF_DB_GET -- retrieve data from an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- ptr to NULL terminated string to find in db
**  	outbuf -- output buffer
**  	outbuflen -- IN: number of bytes available at outbuf
**  	             OUT: number of bytes written to outbuf
**  	exists -- pointer to a "_Bool" updated to be TRUE if the record
**  	          was found, FALSE otherwise (may be NULL)
**	lock -- lock for blocking concurrent access (may be NULL)
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
*/

int
dkimf_db_get(DB *db, char *buf, void *outbuf, size_t *outbuflen,
             _Bool *exists, pthread_mutex_t *lock)
{
	DBT d;
	DBT q;
	int fd;
	int status;
	int ret;

	assert(db != NULL);
	assert(buf != NULL);

	memset(&d, 0, sizeof d);
	memset(&q, 0, sizeof q);
	q.data = (char *) buf;
	q.size = strlen(q.data);

	ret = 0;

# if DB_VERSION_CHECK(2,0,0)
	d.flags = DB_DBT_USERMEM|DB_DBT_PARTIAL;
# endif /* DB_VERSION_CHECK(2,0,0) */
	d.data = outbuf;
	d.size = (outbuflen == NULL ? 0 : *outbuflen);

	/* establish read-lock */
	fd = -1;
# if DB_VERSION_CHECK(2,0,0)
	status = db->fd(db, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
	status = 0;
	fd = db->fd(db);
# endif /* DB_VERSION_CHECK(2,0,0) */

	/* XXX -- allow multiple readers? */
	if (lock != NULL)
		(void) pthread_mutex_lock(lock);

	if (status == 0 && fd != -1)
	{
# ifdef LOCK_SH
		status = flock(fd, LOCK_SH);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "flock(LOCK_SH): %s",
			       strerror(errno));
		}
# else /* LOCK_SH */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_RDLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "fcntl(F_RDLCK): %s",
			       strerror(errno));
		}
# endif /* LOCK_SH */
	}

# if DB_VERSION_CHECK(2,0,0)
	status = db->get(db, NULL, &q, &d, 0);
	if (status == 0)
	{
		if (exists != NULL)
			*exists = TRUE;
		
		if (outbuflen != NULL)
			*outbuflen = d.size;

		ret = 0;
	}
	else if (status == DB_NOTFOUND)
	{
		if (exists != NULL)
			*exists = FALSE;
		ret = 0;
	}
	else
	{
		ret = status;
	}
# else /* DB_VERSION_CHECK(2,0,0) */
	status = db->get(db, &q, &d, 0);
	if (status == 1)
	{
		if (exists != NULL)
			*exists = FALSE;
		ret = 0;
	}
	else if (status == 0)
	{
		if (exists != NULL)
			*exists = TRUE;

		if (outbuflen != NULL)
			*outbuflen = d.size;

		ret = 0;
	}
	else
	{
		ret = errno;
	}
# endif /* DB_VERSION_CHECK(2,0,0) */

	/* surrender read-lock */
	if (fd != -1)
	{
# ifdef LOCK_SH
		status = flock(fd, LOCK_UN);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "flock(LOCK_UN): %s",
			       strerror(errno));
		}
# else /* LOCK_SH */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_UNLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "fcntl(F_UNLCK): %s",
			       strerror(errno));
		}
# endif /* LOCK_SH */
	}

	if (lock != NULL)
		(void) pthread_mutex_unlock(lock);

	return ret;
}

/*
**  DKIMF_DB_PUT -- store a key/data pair in an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- ptr to NULL terminated string to use as key
**  	outbuf -- data buffer
**  	outbuflen -- number of bytes at outbuf to use as data
**	lock -- lock for blocking concurrent access (may be NULL)
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
*/

int
dkimf_db_put(DB *db, char *buf, void *outbuf, size_t outbuflen,
             pthread_mutex_t *lock)
{
	DBT d;
	DBT q;
	int fd;
	int status;
	int ret;

	assert(db != NULL);
	assert(buf != NULL);
	assert(outbuf != NULL);

	memset(&d, 0, sizeof d);
	memset(&q, 0, sizeof q);
	d.data = outbuf;
	d.size = outbuflen;
	q.data = (char *) buf;
	q.size = strlen(q.data);

	ret = 0;

	/* establish write-lock */
	fd = -1;
# if DB_VERSION_CHECK(2,0,0)
	status = db->fd(db, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
	status = 0;
	fd = db->fd(db);
# endif /* DB_VERSION_CHECK(2,0,0) */

	if (lock != NULL)
		(void) pthread_mutex_lock(lock);

	if (status == 0 && fd != -1)
	{
# ifdef LOCK_EX
		status = flock(fd, LOCK_EX);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "flock(LOCK_EX): %s",
			       strerror(errno));
		}
# else /* LOCK_EX */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_WRLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "fcntl(F_RDLCK): %s",
			       strerror(errno));
		}
# endif /* LOCK_EX */
	}

# if DB_VERSION_CHECK(2,0,0)
	status = db->put(db, NULL, &q, &d, 0);
	if (status == 0)
		ret = 0;
	else
		ret = status;
# else /* DB_VERSION_CHECK(2,0,0) */
	status = db->put(db, &q, &d, 0);
	if (status == 1)
		ret = -1;
	else if (status == 0)
		ret = 0;
	else
		ret = errno;
# endif /* DB_VERSION_CHECK(2,0,0) */

	/* surrender write-lock */
	if (fd != -1)
	{
# ifdef LOCK_UN
		status = flock(fd, LOCK_UN);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "flock(LOCK_UN): %s",
			       strerror(errno));
		}
# else /* LOCK_UN */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_UNLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "fcntl(F_UNLCK): %s",
			       strerror(errno));
		}
# endif /* LOCK_UN */
	}

	if (lock != NULL)
		(void) pthread_mutex_unlock(lock);

	return ret;
}

/*
**  DKIMF_DB_DEL -- delete a key/data pair from an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- ptr to NULL terminated string to use as key
**	lock -- lock for blocking concurrent access (may be NULL)
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
*/

int
dkimf_db_delete(DB *db, char *buf, pthread_mutex_t *lock)
{
	DBT q;
	int fd;
	int status;
	int ret;

	assert(db != NULL);
	assert(buf != NULL);

	memset(&q, 0, sizeof q);
	q.data = (char *) buf;
	q.size = strlen(q.data);

	ret = 0;

	/* establish write-lock */
	fd = -1;
# if DB_VERSION_CHECK(2,0,0)
	status = db->fd(db, &fd);
# else /* DB_VERSION_CHECK(2,0,0) */
	status = 0;
	fd = db->fd(db);
# endif /* DB_VERSION_CHECK(2,0,0) */

	if (lock != NULL)
		(void) pthread_mutex_lock(lock);

	if (status == 0 && fd != -1)
	{
# ifdef LOCK_EX
		status = flock(fd, LOCK_EX);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "flock(LOCK_EX): %s",
			       strerror(errno));
		}
# else /* LOCK_EX */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_WRLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "fcntl(F_RDLCK): %s",
			       strerror(errno));
		}
# endif /* LOCK_EX */
	}

# if DB_VERSION_CHECK(2,0,0)
	status = db->del(db, NULL, &q, 0);
	if (status == 0)
		ret = 0;
	else
		ret = status;
# else /* DB_VERSION_CHECK(2,0,0) */
	status = db->del(db, &q, 0);
	if (status == 1)
		ret = -1;
	else if (status == 0)
		ret = 0;
	else
		ret = errno;
# endif /* DB_VERSION_CHECK(2,0,0) */

	/* surrender write-lock */
	if (fd != -1)
	{
# ifdef LOCK_UN
		status = flock(fd, LOCK_UN);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "flock(LOCK_UN): %s",
			       strerror(errno));
		}
# else /* LOCK_UN */
		struct flock l;

		l.l_start = 0;
		l.l_len = 0;
		l.l_type = F_UNLCK;
		l.l_whence = SEEK_SET;

		status = fcntl(fd, F_SETLKW, &l);

		if (status != 0 && dolog)
		{
			syslog(LOG_WARNING, "fcntl(F_UNLCK): %s",
			       strerror(errno));
		}
# endif /* LOCK_UN */
	}

	if (lock != NULL)
		(void) pthread_mutex_unlock(lock);

	return ret;
}
#endif /* USE_DB */
