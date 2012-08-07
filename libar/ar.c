/*
**  Copyright (c) 2004-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, The OpenDKIM Project.  All rights reserved.
*/

/* OS stuff */
#if HPUX11
# define _XOPEN_SOURCE_EXTENDED
#endif /* HPUX11 */

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#if SOLARIS > 20700
# include <iso/limits_iso.h>
#endif /* SOLARIS > 20700 */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ctype.h>
#include <resolv.h>
#include <netdb.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>

/* important macros */
#define AR_MAXHOSTNAMELEN	256

#define	ARDEBUGOUT	"/var/tmp/ardebug.out"

#define	BUFRSZ		1024

#ifndef MAXPACKET
# define MAXPACKET	8192
#endif /* ! MAXPACKET */

#define QUERYLIMIT	32768

#ifndef MAX
# define MAX(x,y)	((x) > (y) ? (x) : (y))
#endif /* ! MAX */

#ifndef MIN
# define MIN(x,y)	((x) < (y) ? (x) : (y))
#endif /* ! MIN */

#ifndef MSG_WAITALL
# define MSG_WAITALL	0
#endif /* ! MSG_WAITALL */

#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

/* ar includes */
#include "async-resolv.h"
#include "ar-socket.h"
#include "ar-strl.h"
#include "manual.h"

/*
**  DATA TYPES
*/

struct ar_query
{
	int			q_depth;
	int			q_flags;
	int			q_class;
	int			q_type;
	int			q_id;
	int			q_tries;
	size_t			q_buflen;
	size_t			q_replylen;
	int *			q_errno;
	unsigned char *		q_buf;
	pthread_cond_t		q_reply;
	pthread_mutex_t		q_lock;
	struct ar_query *	q_next;
	struct timeval		q_timeout;
	struct timeval		q_sent;
	char			q_name[AR_MAXHOSTNAMELEN + 1];
};

#ifdef AF_INET6
typedef struct sockaddr_storage SOCKADDR;
#else /* AF_INET6 */
typedef struct sockaddr SOCKADDR;
#endif /* AF_INET6 */

struct ar_libhandle
{
	int			ar_drun;
	int			ar_partwrite;
	int			ar_fullwrite;
	int			ar_nsfd;
	int			ar_nsfdpf;
	int			ar_control[2];
	int			ar_nscount;
	int			ar_nsidx;
	int			ar_deaderrno;
	int			ar_resend;
	int			ar_retries;
	u_int			ar_flags;
	size_t			ar_tcpmsglen;
	size_t			ar_tcpbuflen;
	size_t			ar_tcpbufidx;
	size_t			ar_writelen;
	size_t			ar_querybuflen;
	pthread_t		ar_dispatcher;
	pthread_mutex_t		ar_lock;
	unsigned char *		ar_querybuf;
	unsigned char *		ar_tcpbuf;
	SOCKADDR *		ar_nsaddrs;
	AR_SOCKET_SET		ar_css;		/* client socket set */
	AR_SOCKET_SET		ar_dss;		/* dispatcher socket set */
	void *			(*ar_malloc) (void *closure, size_t nbytes);
	void			(*ar_free) (void *closure, void *p);
	void *			ar_closure;
	struct ar_query *	ar_pending;	/* to be sent (queue head) */
	struct ar_query *	ar_pendingtail;	/* to be sent (queue tail) */
	struct ar_query *	ar_queries;	/* awaiting replies (head) */
	struct ar_query *	ar_queriestail;	/* awaiting replies (tail) */
	struct ar_query *	ar_recycle;	/* recyclable queries */
	struct iovec		ar_iovec[2];	/* I/O vector */
	struct timeval		ar_retry;	/* retry interval */
	struct timeval		ar_deadsince;	/* when we lost all service */
	struct timeval		ar_revivify;	/* how long to play dead */
	struct __res_state	ar_res;		/* resolver data */
};

/*
**  DEFINITIONS
*/

#define	QUERY_INFINIWAIT	0x01		/* infinite wait */
#define	QUERY_REPLY		0x02		/* reply stored */
#define	QUERY_NOREPLY		0x04		/* query expired */
#define	QUERY_ERROR		0x08		/* error sending */
#define	QUERY_RESEND		0x10		/* resend pending */

/*
**  PROTOTYPES
*/

static void *ar_malloc(AR_LIB, size_t);
static void ar_free(AR_LIB lib, void *ptr);
static int ar_res_init(AR_LIB);

/*
**  GLOBALS
*/

#ifdef ARDEBUG
static FILE *debugout;
#endif /* ARDEBUG */

/*
**  ========================= PRIVATE FUNCTIONS =========================
*/

#ifdef ARDEBUG
/*
**  AR_DEBUG_INIT -- set up debugging output
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

static void
ar_debug_init(void)
{
	debugout = fopen(ARDEBUGOUT, "w");
	if (debugout != NULL)
		setlinebuf(debugout);
}

/*
**  AR_DEBUG_STOP -- close debugging output
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

static void
ar_debug_stop(void)
{
	fclose(debugout);
}
/*
**  AR_DEBUG_LOCKINIT -- print lock information
**
**  Parameters:
** 	lock -- lock to be created
** 	attr -- lock attributes
**  	line -- line number where this was called
**
**  Return value:
**  	See pthread_mutex_lock().
*/

static int
ar_debug_lockinit(pthread_mutex_t *lock, pthread_mutexattr_t *attr, int line)
{
	fprintf(debugout, "%d: %lu: mutex_init(%p, %p)\n", line,
	        pthread_self(), lock, attr);

	return pthread_mutex_init(lock, attr);
}

/*
**  AR_DEBUG_LOCK -- print lock information
**
**  Parameters:
** 	lock -- lock to be retrieved
**  	line -- line number where this was called
**
**  Return value:
**  	See pthread_mutex_lock().
*/

static int
ar_debug_lock(pthread_mutex_t *lock, int line)
{
	int ret;

	fprintf(debugout, "%d: %lu: lock(%p)\n", line,
	        pthread_self(), lock);

	ret = pthread_mutex_lock(lock);

	fprintf(debugout, "%d: %lu: lock acquired\n", line, pthread_self());

	return ret;
}

/*
**  AR_DEBUG_UNLOCK -- print unlock information
**
**  Parameters:
** 	lock -- lock to be released
**  	line -- line number where this was called
**
**  Return value:
**  	See pthread_mutex_unlock().
*/

static int
ar_debug_unlock(pthread_mutex_t *lock, int line)
{
	fprintf(debugout, "%d: %lu: unlock(%p)\n", line,
	        pthread_self(), lock);

	return pthread_mutex_unlock(lock);
}

/*
**  AR_DEBUG_SIGNAL -- signal condition
**
**  Parameters:
** 	cond -- condition to be signaled
**  	line -- line number where this was called
**
**  Return value:
**  	See pthread_mutex_unlock().
*/

static int
ar_debug_signal(pthread_cond_t *cond, int line)
{
	fprintf(debugout, "%d: %lu: signal(%p)\n", line,
	        pthread_self(), cond);

	return pthread_cond_signal(cond);
}

/*
**  AR_DEBUG_CONDWAIT -- wait for a condition
**
**  Parameters:
**  	cond -- condition variable
**  	lock -- mutex
**  	line -- line number
**
**  Return value:
**  	See pthread_cond_wait().
*/

static int
ar_debug_condwait(pthread_cond_t *cond, pthread_mutex_t *lock, int line)
{
	int ret;

	fprintf(debugout, "%d: %lu: wait(%p, %p)\n", line,
	        pthread_self(), cond, lock);

	ret = pthread_cond_wait(cond, lock);

	fprintf(debugout, "%d: %lu: signal received\n", cond, lock);

	return ret;
}

/*
**  AR_DEBUG_CONDTIMEDWAIT -- wait for a condition with timeout
**
**  Parameters:
**  	cond -- condition variable
**  	lock -- mutex
**  	timeout -- timeout
**  	line -- line number
**
**  Return value:
**  	See pthread_cond_timedwait().
*/

static int
ar_debug_condtimedwait(pthread_cond_t *cond, pthread_mutex_t *lock,
                       struct timespec *timeout, int line)
{
	int ret;

	fprintf(debugout, "%d: %lu: timedwait(%p, %p, %p)\n", line,
	        pthread_self(), cond, lock, timeout);

	ret = pthread_cond_timedwait(cond, lock, timeout);

	fprintf(debugout, "%d: %lu: %s\n", line, pthread_self(),
	        ret == ETIMEDOUT ? "timeout" : "signal received");

	return ret;
}

# define pthread_cond_signal(x)		ar_debug_signal((x), __LINE__)
# define pthread_cond_timedwait(x,y,z)	ar_debug_condtimedwait((x), (y), (z), __LINE__)
# define pthread_cond_wait(x,y)		ar_debug_condwait((x), (y), __LINE__)
# define pthread_mutex_init(x,y)	ar_debug_lockinit((x), (y), __LINE__)
# define pthread_mutex_lock(x)		ar_debug_lock((x), __LINE__)
# define pthread_mutex_unlock(x)	ar_debug_unlock((x), __LINE__)
#endif /* ARDEBUG */

/*
**  AR_MALLOC -- allocate memory
**
**  Parameters:
**  	lib -- library handle
**  	bytes -- how many bytes to get
**
**  Return value:
**  	Pointer to newly available memory, or NULL on error.
*/

static void *
ar_malloc(AR_LIB lib, size_t bytes)
{
	assert(lib != NULL);

	if (lib->ar_malloc != NULL)
		return lib->ar_malloc(lib->ar_closure, bytes);
	else
		return malloc(bytes);
}

/*
**  AR_FREE -- release memory
**
**  Parameters:
**  	lib -- library handle
**  	ptr -- pointer to memory to release
**
**  Return value:
**  	None.
*/

static void
ar_free(AR_LIB lib, void *ptr)
{
	assert(lib != NULL);
	assert(ptr != NULL);

	if (lib->ar_free != NULL)
		lib->ar_free(lib->ar_closure, ptr);
	else
		free(ptr);
}

/*
**  AR_SMASHQUEUE -- smash everything in a list of queue handles
**
**  Parameters:
**  	q -- query at the head of the list to clobber
**
**  Return value:
**  	None.
**
**  Notes:
**  	Very destructive.
*/

static void
ar_smashqueue(AR_LIB lib, AR_QUERY q)
{
	AR_QUERY cur;
	AR_QUERY next;

	assert(lib != NULL);

	if (q == NULL)
		return;

	cur = q;
	while (cur != NULL)
	{
		next = cur->q_next;

		ar_free(lib, cur);

		cur = next;
	}
}

/*
**  AR_TIMELEFT -- given a start time and a duration, see how much is left
**
**  Parameters:
**  	start -- start time
**  	length -- run time
**  	remain -- how much time is left (updated)
**
**  Return value:
**   	None.
**
**  Notes:
**  	If "start" is NULL, "length" is taken to be the end time.
*/

static void
ar_timeleft(struct timeval *start, struct timeval *length,
            struct timeval *remain)
{
	struct timeval now;
	struct timeval end;

	assert(length != NULL);
	assert(remain != NULL);

	(void) gettimeofday(&now, NULL);

	if (start == NULL)
	{
		memcpy(&end, length, sizeof end);
	}
	else
	{
		end.tv_sec = start->tv_sec + length->tv_sec;
		end.tv_usec = start->tv_usec + length->tv_usec;
		end.tv_sec += end.tv_usec / 1000000;
		end.tv_usec = end.tv_usec % 1000000;
	}

	if (now.tv_sec > end.tv_sec ||
	    (now.tv_sec == end.tv_sec && now.tv_usec > end.tv_usec))
	{
		remain->tv_sec = 0;
		remain->tv_usec = 0;
	}
	else
	{
		remain->tv_sec = end.tv_sec - now.tv_sec;
		if (end.tv_usec < now.tv_usec)
		{
			remain->tv_sec--;
			remain->tv_usec = end.tv_usec - now.tv_usec + 1000000;
		}
		else
		{
			remain->tv_usec = end.tv_usec - now.tv_usec;
		}
	}
}

/*
**  AR_ELAPSED -- determine whether or not a certain amount of time has
**                elapsed
**
**  Parameters:
**  	start -- start time
**  	length -- run time
**
**  Return value:
**  	TRUE iff length has elapsed since start.
*/

static _Bool
ar_elapsed(struct timeval *start, struct timeval *length)
{
	struct timeval now;
	struct timeval tmp;

	assert(start != NULL);
	assert(length != NULL);

	(void) gettimeofday(&now, NULL);

	tmp.tv_sec = start->tv_sec + length->tv_sec;
	tmp.tv_usec = start->tv_usec + length->tv_usec;
	if (tmp.tv_usec >= 1000000)
	{
		tmp.tv_usec -= 1000000;
		tmp.tv_sec += 1;
	}

	if (tmp.tv_sec < now.tv_sec ||
	    (tmp.tv_sec == now.tv_sec && tmp.tv_usec < now.tv_usec))
		return TRUE;

	return FALSE;
}

/*
**  AR_UNDOT -- remove a trailing dot if there is one
**
**  Parameters:
**  	str -- string to modify
**
**  Return value:
**  	None.
*/

static void
ar_undot(char *str)
{
	char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (*p == '.' && *(p + 1) == '\0')
		{
			*p = '\0';
			break;
		}
	}
}

/*
**  AR_EXPIRED -- see if a query has expired
**
**  Parameters:
**  	q -- query being checked
**
**  Return value:
**  	1 if the query has expired, 0 otherwise
*/

static int
ar_expired(AR_QUERY q)
{
	struct timeval now;

	assert(q != NULL);

	if (q->q_timeout.tv_sec == 0 || (q->q_flags & QUERY_INFINIWAIT) != 0)
		return 0;

	(void) gettimeofday(&now, NULL);

	if (q->q_timeout.tv_sec < now.tv_sec)
		return 1;

	if (q->q_timeout.tv_sec == now.tv_sec &&
	    q->q_timeout.tv_usec < now.tv_usec)
		return 1;

	return 0;
}

/*
**  AR_ALLDEAD -- mark all pending and active queries dead
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	None.
*/

static void
ar_alldead(AR_LIB lib)
{
	AR_QUERY q;

	assert(lib != NULL);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: marking all queries dead");

	/* tack the pending list to the end of the active list */
	if (lib->ar_pending != NULL)
	{
		if (lib->ar_queriestail != NULL)
		{
			lib->ar_queriestail->q_next = lib->ar_pending;
		}
		else
		{
			lib->ar_queries = lib->ar_pending;
		}

		lib->ar_queriestail = lib->ar_pendingtail;

		lib->ar_pending = NULL;
		lib->ar_pendingtail = NULL;
	}

	/* mark everything with QUERY_ERROR and wake them all up */
	for (q = lib->ar_queries; q != NULL; q = q->q_next)
	{
		pthread_mutex_lock(&q->q_lock);

		q->q_flags |= QUERY_ERROR;
		if (q->q_errno != NULL)
			*q->q_errno = QUERY_ERRNO_SERVICE;

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
			syslog(LOG_DEBUG, "arlib: signaling %p", q);

		pthread_cond_signal(&q->q_reply);
		pthread_mutex_unlock(&q->q_lock);
	}
}

/*
**  AR_REQUERY -- position an active query at the front of the pending queue
**
**  Parameters:
**  	lib -- library handle
**  	query -- query to send
**
**  Return value:
**  	None.
**
**  Notes:
**  	Presumes the caller has acquired a lock on the "lib" handle.
*/

static void
ar_requery(AR_LIB lib, AR_QUERY query)
{
	AR_QUERY q;
	AR_QUERY last;

	assert(lib != NULL);
	assert(query != NULL);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: requerying %p", query);

	/* remove from active queries */
	for (q = lib->ar_queries, last = NULL;
	     q != NULL;
	     last = q, q = q->q_next)
	{
		if (query == q)
		{
			if (last == NULL)
			{
				lib->ar_queries = q->q_next;
				if (lib->ar_queries == NULL)
					lib->ar_queriestail = NULL;

			}
			else
			{
				last->q_next = q->q_next;
				if (lib->ar_queriestail == q)
					lib->ar_queriestail = last;
			}

			if ((q->q_flags & QUERY_RESEND) != 0)
				lib->ar_resend--;
		}
	}

	/* insert at front of pending queue */
	if (lib->ar_pending == NULL)
	{
		lib->ar_pending = query;
		lib->ar_pendingtail = query;
		query->q_next = NULL;
	}
	else
	{
		query->q_next = lib->ar_pending;
		lib->ar_pending = query;
	}
}

/*
**  AR_REQUEUE -- arrange to re-send everything after a reconnect
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	None.
**
**  Notes:
**  	Jobs to retry get priority over currently pending jobs.
**  	Presumes the caller holds the lock in the library handle.
*/

static void
ar_requeue(AR_LIB lib)
{
	assert(lib != NULL);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: requeueing everything");

	if (lib->ar_queries != NULL)
	{
		int status;
		fd_set wfds;
		AR_QUERY x = NULL;
		struct timeval stimeout;

		if (lib->ar_pending != NULL)
		{
			lib->ar_queriestail->q_next = lib->ar_pending;
		}
		else
		{
			lib->ar_pendingtail = lib->ar_queriestail;
		}

		lib->ar_pending = lib->ar_queries;

		lib->ar_queries = NULL;
		lib->ar_queriestail = NULL;

		ar_socket_reset(lib->ar_dss);
		ar_socket_add(lib->ar_dss, lib->ar_control[0],
		              AR_SOCKET_EVENT_WRITE);
		status = ar_socket_wait(lib->ar_dss, 0);
		if (status == 1)
			(void) write(lib->ar_control[0], &x, sizeof x);
	}
}

/*
**  AR_RECONNECT -- reconnect when TCP service dies
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
** 	TRUE iff reconnect was successful.
**
**  Notes:
**  	If reconnection was impossible, all queries are marked with
**  	QUERY_ERROR and signalled immediately.  ar_flags is marked with
**  	AR_FLAG_DEAD, preventing further calls to ar_addquery().
**  	Assumes the caller holds ar_lock.
*/

static _Bool
ar_reconnect(AR_LIB lib)
{
	int c;
	int saveerrno;
	int nsnum;
	int socklen;
	struct sockaddr *sa;

	assert(lib != NULL);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: attempting reconnect");

	if ((lib->ar_flags & AR_FLAG_RECONNECT) == 0)
		return TRUE;

	if ((lib->ar_flags & AR_FLAG_USETCP) == 0)
	{
		ar_requeue(lib);
		lib->ar_flags &= ~AR_FLAG_RECONNECT;
		return TRUE;
	}

	close(lib->ar_nsfd);
	lib->ar_nsfd = -1;
	lib->ar_nsfdpf = -1;
	lib->ar_partwrite = 0;
	lib->ar_fullwrite = 0;

	/* try to connect to someone */
	for (c = 0; c < lib->ar_nscount; c++)
	{
		nsnum = (c + lib->ar_nsidx) % lib->ar_nscount;

		sa = (struct sockaddr *) &lib->ar_nsaddrs[nsnum];

#ifdef AF_INET6
		if (sa->sa_family == AF_INET6)
			socklen = sizeof(struct sockaddr_in6);
		else
			socklen = sizeof(struct sockaddr_in);
#else /* AF_INET6 */
		socklen = sizeof(struct sockaddr_in);
#endif /* AF_INET6 */

		lib->ar_nsfd = socket(sa->sa_family, SOCK_STREAM, 0);
		if (lib->ar_nsfd == -1)
		{
			if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
			{
				syslog(LOG_DEBUG, "arlib: socket(): %s",
				       strerror(errno));
			}

			continue;
		}

		lib->ar_nsfdpf = sa->sa_family;

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			uint32_t addr;
			struct sockaddr_in *si;

			si = (struct sockaddr_in *) sa;
			addr = si->sin_addr.s_addr;
			syslog(LOG_DEBUG,
			       "arlib: trying nameserver %d.%d.%d.%d",
			       (addr >> 24), (addr >> 16) & 0xff,
			       (addr >> 8) & 0xff, addr & 0xff);
		}

		if (connect(lib->ar_nsfd, sa, socklen) == 0)
		{
			if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				syslog(LOG_DEBUG, "arlib: connected");

			lib->ar_flags &= ~AR_FLAG_RECONNECT;
			ar_requeue(lib);
			return TRUE;
		}

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: connect(): %s",
			       strerror(errno));
		}

		close(lib->ar_nsfd);
		lib->ar_nsfd = -1;
		lib->ar_nsfdpf = -1;
	}

	saveerrno = errno;

	/* unable to reconnect; arrange to terminate */
	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: failed to reconnect");
	ar_alldead(lib);
	(void) gettimeofday(&lib->ar_deadsince, NULL);
	lib->ar_flags |= AR_FLAG_DEAD;
	lib->ar_deaderrno = saveerrno;

	return FALSE;
}

/*
**  AR_SENDQUERY -- send a query
**
**  Parameters:
**  	lib -- library handle
**  	query -- query to send
**
**  Return value:
**  	TRUE iff the message was able to be sent.
**
**  Notes:
**  	Caller must already hold the query-specific lock.
*/

static _Bool
ar_sendquery(AR_LIB lib, AR_QUERY query)
{
	size_t n;
	HEADER hdr;

	assert(lib != NULL);
	assert(query != NULL);

	if (lib->ar_retries > 0 && query->q_tries == lib->ar_retries)
	{
		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: %p retry count exceeded",
			       query);
		}

		query->q_flags |= QUERY_ERROR;
		if (query->q_errno != NULL)
			*query->q_errno = QUERY_ERRNO_RETRIES;
		pthread_cond_signal(&query->q_reply);
		return FALSE;
	}
	
	for (;;)
	{
#if (defined(__RES) && (__RES <= 19960801))
		n = res_mkquery(QUERY, query->q_name, query->q_class,
		                query->q_type, NULL, 0, NULL, lib->ar_querybuf,
		                lib->ar_querybuflen);
#else /* defined(__RES) && (__RES <= 19960801) */
		n = res_nmkquery(&lib->ar_res, QUERY, query->q_name,
		                 query->q_class, query->q_type, NULL, 0,
		                 NULL, lib->ar_querybuf, lib->ar_querybuflen);
#endif /* defined(__RES) && (__RES <= 19960801) */

		if (n != (size_t) -1)
		{
			lib->ar_writelen = n;
			break;
		}

		if (lib->ar_querybuflen >= QUERYLIMIT)
		{
			query->q_flags |= QUERY_ERROR;
			if (query->q_errno != NULL)
				*query->q_errno = QUERY_ERRNO_TOOBIG;
			pthread_cond_signal(&query->q_reply);
			return FALSE;
		}

		ar_free(lib, lib->ar_querybuf);
		lib->ar_querybuflen *= 2;
		lib->ar_querybuf = ar_malloc(lib, lib->ar_querybuflen);
	}

	memcpy(&hdr, lib->ar_querybuf, sizeof hdr);
	query->q_id = hdr.id;

#ifdef DEBUG
	printf("*** SEND '%s' class=%d type=%d id=%d time=%d\n", query->q_name,
	       query->q_class, query->q_type, hdr.id, time(NULL));
#endif /* DEBUG */

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
	{
		syslog(LOG_DEBUG, "arlib: sending %p '%s' id=%d", query,
		       query->q_name, query->q_id);
	}

	/* send it */
	if ((lib->ar_flags & AR_FLAG_USETCP) != 0)
	{
		u_short len;

		len = htons(n);
		lib->ar_iovec[0].iov_base = (void *) &len;
		lib->ar_iovec[0].iov_len = sizeof len;
		lib->ar_iovec[1].iov_base = (void *) lib->ar_querybuf;
		lib->ar_iovec[1].iov_len = lib->ar_writelen;

		n = writev(lib->ar_nsfd, lib->ar_iovec, 2);

		lib->ar_fullwrite = lib->ar_iovec[0].iov_len + lib->ar_iovec[1].iov_len;
	}
	else
	{
		int nsnum;
		int socklen;
		struct sockaddr *sa;

		nsnum = query->q_tries % lib->ar_nscount;

		sa = (struct sockaddr *) &lib->ar_nsaddrs[nsnum];

		/* change to the right family if needed */
		if (sa->sa_family != lib->ar_nsfdpf)
		{
			close(lib->ar_nsfd);
			lib->ar_nsfdpf = -1;

			lib->ar_nsfd = socket(sa->sa_family,
			                      SOCK_DGRAM, 0);
			if (lib->ar_nsfd != -1)
				lib->ar_nsfdpf = sa->sa_family;
		}

#ifdef AF_INET6
		if (sa->sa_family == AF_INET6)
			socklen = sizeof(struct sockaddr_in6);
		else
			socklen = sizeof(struct sockaddr_in);
#else /* AF_INET */
		socklen = sizeof(struct sockaddr_in);
#endif /* AF_INET */

		n = sendto(lib->ar_nsfd, lib->ar_querybuf,
		           lib->ar_writelen, 0, sa, socklen);

		lib->ar_fullwrite = lib->ar_writelen;
	}

	if (n == (size_t) -1)
	{
		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: %p sendto/writev failed: %s",
			       query, strerror(errno));
		}

		lib->ar_flags |= AR_FLAG_RECONNECT;
		query->q_flags |= QUERY_ERROR;
		if (query->q_errno != NULL)
			*query->q_errno = errno;
		pthread_cond_signal(&query->q_reply);
		return FALSE;
	}
	else
	{
		lib->ar_partwrite = n;
	}

	query->q_tries += 1;
	(void) gettimeofday(&query->q_sent, NULL);

	return TRUE;
}

/*
**  AR_ANSCOUNT -- count received answers
**
**  Parameters:
**  	buf -- pointer to a packet
**  	len -- bytes available at "buf"
**
**  Return value:
**  	Count of actual answers (may be smaller than ancount).
*/

static int
ar_anscount(unsigned char *buf, size_t len)
{
	int ret = 0;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t class;
	uint16_t type;
	uint16_t rrsize;
	uint32_t ttl;
	int n;
	unsigned char *cp;
	unsigned char *eom;
	HEADER *hdr;
	unsigned char name[AR_MAXHOSTNAMELEN + 1];

	assert(buf != NULL);

	hdr = (HEADER *) buf;
	cp = buf + HFIXEDSZ;
	eom = buf + len;

	qdcount = ntohs((unsigned short) hdr->qdcount);
	ancount = ntohs((unsigned short) hdr->ancount);

	for (; qdcount > 0; qdcount--)
	{
		if ((n = dn_skipname(cp, eom)) < 0)
			break;
		cp += n;

		if (cp + INT16SZ + INT16SZ > eom)
			break;

		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (qdcount > 0)
		return 0;

	if (ancount == 0)
		return 0;

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount > 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) buf, eom, cp,
		                   (RES_UNC_T) name, sizeof name)) < 0)
			return ret;

		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ + INT32SZ > eom)
			return ret;

		GETSHORT(type, cp);
		GETSHORT(class, cp);
		GETLONG(ttl, cp);

		/* get payload length */
		if (cp + INT16SZ > eom)
			return ret;

		GETSHORT(rrsize, cp);

		/* is it not all there? */
		if (cp + rrsize > eom)
			return ret;

		/* it is; count the reply */
		ret++;
		cp += rrsize;
	}

	return ret;
}

/*
**  AR_DISPATCHER -- dispatcher thread
**
**  Parameters:
**  	tp -- thread pointer; miscellaneous data set up at init time
**
**  Return value:
**  	Always NULL.
*/

static void *
ar_dispatcher(void *tp)
{
	_Bool usetimeout;
	_Bool reconnect;
	int status;
	int to;
	size_t r;
	AR_LIB lib;
	AR_QUERY q;
	u_char *buf;
	struct timeval timeout;
	struct timeval timeleft;
	sigset_t set;

	assert(tp != NULL);

	lib = tp;

	pthread_mutex_lock(&lib->ar_lock);

	lib->ar_resend = 0;

	/* block signals that should be caught elsewhere */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: dispatcher starting");

	for (;;)
	{
#ifdef ARDEBUG
		/* truncate tracing output if everything is synched up */
		if (lib->ar_pending == NULL && lib->ar_queries == NULL)
		{
			rewind(debugout);
			ftruncate(fileno(debugout), 0);
		}
#endif /* ARDEBUG */

		/* if we're dead, see if it's time to revivify */
		if ((lib->ar_flags & AR_FLAG_DEAD) != 0)
		{
			if (ar_elapsed(&lib->ar_deadsince,
			               &lib->ar_revivify))
			{
				if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				{
					syslog(LOG_DEBUG,
					       "arlib: dispatcher revivifying");
				}
				lib->ar_flags &= ~AR_FLAG_DEAD;
			}
		}

		/* attempt to reconnect if needed */
		if ((lib->ar_flags & AR_FLAG_DEAD) == 0 &&
		    (lib->ar_nsfd == -1 ||
		     (lib->ar_flags & AR_FLAG_RECONNECT) != 0))
		    	(void) ar_reconnect(lib);

		/* check on the control descriptor and the NS descriptor */
		ar_socket_reset(lib->ar_dss);

		ar_socket_add(lib->ar_dss, lib->ar_control[1],
		              AR_SOCKET_EVENT_READ);

		if ((lib->ar_pending != NULL || lib->ar_resend > 0) ||
		    lib->ar_partwrite < lib->ar_fullwrite)
		{
			ar_socket_add(lib->ar_dss, lib->ar_nsfd,
			              AR_SOCKET_EVENT_WRITE);
		}

		if (lib->ar_nsfd != -1)
		{
			ar_socket_add(lib->ar_dss, lib->ar_nsfd,
			              AR_SOCKET_EVENT_READ);
		}

		/* determine how long to wait */
		if ((lib->ar_flags & AR_FLAG_DEAD) != 0)
			timeout.tv_sec = AR_DEFREVIVIFY;
		else
			timeout.tv_sec = AR_MAXTIMEOUT;
		timeout.tv_usec = 0;

		usetimeout = (lib->ar_queries != NULL);

		for (q = lib->ar_queries; q != NULL; q = q->q_next)
		{
			/* skip queries for which we're no longer waiting */
			if ((q->q_flags & (QUERY_ERROR|QUERY_REPLY|QUERY_NOREPLY)) != 0)
				continue;

			/* check for absolute timeout */
			if (q->q_timeout.tv_sec != 0 &&
			    (q->q_flags & QUERY_INFINIWAIT) == 0)
			{
				ar_timeleft(NULL, &q->q_timeout, &timeleft);
				if (timeleft.tv_sec < timeout.tv_sec ||
				    (timeleft.tv_sec == timeout.tv_sec &&
				     timeleft.tv_usec < timeout.tv_usec))
				{
					memcpy(&timeout, &timeleft,
					       sizeof timeout);
				}
			}

			/* check for re-send timeout */
			ar_timeleft(&q->q_sent, &lib->ar_retry, &timeleft);
			if (timeleft.tv_sec < timeout.tv_sec ||
			    (timeleft.tv_sec == timeout.tv_sec &&
			     timeleft.tv_usec < timeout.tv_usec))
				memcpy(&timeout, &timeleft, sizeof timeout);
		}

		pthread_mutex_unlock(&lib->ar_lock);

		to = 1000 * timeout.tv_sec + timeout.tv_usec / 1000;

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			if (usetimeout)
			{
				syslog(LOG_DEBUG,
				       "arlib: dispatcher pausing (%u.%06us)",
				       timeout.tv_sec, timeout.tv_usec);
			}
			else
			{
				syslog(LOG_DEBUG, "arlib: dispatcher pausing");
			}
		}

		/* XXX -- effect a poll if we knew there was more pending */
		status = ar_socket_wait(lib->ar_dss, usetimeout ? to : -1);
		if (status == -1)
		{
			if (errno == EINTR)
			{
				pthread_mutex_lock(&lib->ar_lock);
				continue;
			}
			else
			{
				assert(status >= 0);
			}
		}

		buf = NULL;

		/* read what's available from the nameserver for dispatch */
		if (lib->ar_nsfd != -1 &&
		    ar_socket_check(lib->ar_dss, lib->ar_nsfd,
		                    AR_SOCKET_EVENT_READ) == 1)
		{
			if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				syslog(LOG_DEBUG, "arlib: reply received");

			if ((lib->ar_flags & AR_FLAG_USETCP) == 0)
			{
				r = recvfrom(lib->ar_nsfd, lib->ar_querybuf,
				             lib->ar_querybuflen, 0, NULL,
				             NULL);

				if (r == (size_t) -1)
				{
					pthread_mutex_lock(&lib->ar_lock);
					continue;
				}

				buf = lib->ar_querybuf;
			}
			else if (lib->ar_tcpmsglen == 0)
			{
				uint16_t len;
				_Bool err = FALSE;

				/* get the length */
				len = 0;
				r = recvfrom(lib->ar_nsfd, &len, sizeof len,
				             MSG_WAITALL, NULL, NULL);

				if (r == (size_t) -1)
				{
					if (errno == EINTR)
					{
						pthread_mutex_lock(&lib->ar_lock);
						continue;
					}
					else
					{
						err = TRUE;
					}
				}
				else if (r == 0)
				{
					err = TRUE;
				}
				else if (r < sizeof len)
				{
					pthread_mutex_lock(&lib->ar_lock);
					continue;
				}

				if (err)
				{
					pthread_mutex_lock(&lib->ar_lock);

					/* request a reconnect */
		     			lib->ar_flags |= AR_FLAG_RECONNECT;

					/* arrange to re-send everything */
					ar_requeue(lib);

					continue;
				}

				lib->ar_tcpmsglen = ntohs(len);
				lib->ar_tcpbufidx = 0;

				/* allocate a buffer */
				if (lib->ar_tcpbuf == NULL ||
				    lib->ar_tcpbuflen < ntohs(len))
				{
					if (lib->ar_tcpbuf != NULL)
					{
						ar_free(lib, lib->ar_tcpbuf);
						lib->ar_tcpbuf = NULL;
					}

					lib->ar_tcpbuf = ar_malloc(lib,
					                           ntohs(len));
					lib->ar_tcpbuflen = ntohs(len);
				}
			}
			else
			{
				_Bool err = FALSE;
				size_t rem;
				ssize_t part;
				u_char *where;

				where = lib->ar_tcpbuf + lib->ar_tcpbufidx;
				rem = lib->ar_tcpmsglen - lib->ar_tcpbufidx;

				/* grab next chunk (may be in pieces) */
				r = 0;

				while (lib->ar_tcpbufidx < lib->ar_tcpmsglen)
				{
					part = recvfrom(lib->ar_nsfd,
					                where, rem,
					                0, NULL, NULL);

					if (part == 0 || part == (size_t) -1)
					{
						if (errno == EINTR)
							continue;

						err = TRUE;
						break;
					}


					r += part;
					where += part;
					lib->ar_tcpbufidx += part;
				}

				if (err)
				{
					pthread_mutex_lock(&lib->ar_lock);

					/* request a reconnect */
		     			lib->ar_flags |= AR_FLAG_RECONNECT;

					/* arrange to re-send everything */
					ar_requeue(lib);

					continue;
				}

				if (lib->ar_tcpbufidx == lib->ar_tcpmsglen)
				{
					buf = lib->ar_tcpbuf;
					r = lib->ar_tcpmsglen;
				}
			}
		}

		pthread_mutex_lock(&lib->ar_lock);

		if (buf != NULL)		/* something to parse */
		{
			_Bool requeued = FALSE;
			HEADER hdr;

			if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
			{
				syslog(LOG_DEBUG,
				       "arlib: full reply received");
			}

			/* reset TCP read mode */
			lib->ar_tcpmsglen = 0;

			/* truncate extra data */
			if (r > MAXPACKET)
				r = MAXPACKET;

			/* copy header */
			memcpy(&hdr, buf, sizeof hdr);

			/* check for truncation in UDP mode */
			if (hdr.rcode == NOERROR && hdr.tc &&
			    (lib->ar_flags & AR_FLAG_USETCP) == 0 &&
			    ((lib->ar_flags & AR_FLAG_TRUNCCHECK) == 0 ||
			     ar_anscount(buf, r) == 0))
			{
				if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				{
					syslog(LOG_DEBUG,
					       "arlib: truncation detected");
				}

				/* request a reconnect */
				lib->ar_flags |= AR_FLAG_USETCP;
		     		lib->ar_flags |= AR_FLAG_RECONNECT;

				/* arrange to re-send everything */
				ar_requeue(lib);

				continue;
			}

			/* find the matching query */
			for (q = lib->ar_queries;
			     q != NULL;
			     q = q->q_next)
			{
				pthread_mutex_lock(&q->q_lock);
				if (q->q_id == hdr.id)
				{
					pthread_mutex_unlock(&q->q_lock);
					break;
				}
				pthread_mutex_unlock(&q->q_lock);
			}

#ifdef DEBUG
			printf("*** RECEIVE id=%d time=%d\n", hdr.id,
			       time(NULL));
#endif /* DEBUG */

			if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
			{
				if (q != NULL)
				{
					syslog(LOG_DEBUG,
					       "arlib: %p (id %d) reply received",
					       q, q->q_id);
				}
				else
				{
					syslog(LOG_DEBUG,
					       "arlib: abandoned reply %d received",
					       hdr.id);
				}
			}

			/* don't recurse if user buffer is too small */
			if (q != NULL && r > q->q_buflen)
				q->q_depth = 0;

			/* check CNAME and depth */
			if (q != NULL && q->q_depth > 0)
			{
				int n;
				int class;
				int type;
				int qdcount;
				int ancount;
				size_t anslen;
				u_char *cp;
				u_char *eom;

				anslen = r;
				cp = (u_char *) buf + HFIXEDSZ;
				eom = (u_char *) buf + anslen;

				qdcount = ntohs((unsigned short) hdr.qdcount);
				ancount = ntohs((unsigned short) hdr.ancount);

				for (; qdcount > 0; qdcount--)
				{
					if ((n = dn_skipname(cp, eom)) < 0)
						break;
					cp += n;

					if (cp + INT16SZ + INT16SZ > eom)
						break;

					GETSHORT(type, cp);
					GETSHORT(class, cp);
				}

				if (hdr.rcode == NOERROR || ancount == 0)
				{
					if ((n = dn_skipname(cp, eom)) < 0)
						continue;
					cp += n;

					GETSHORT(type, cp);
					GETSHORT(class, cp);
					cp += INT32SZ;

					/* CNAME found; recurse */
					if (type == T_CNAME)
					{
						char cname[AR_MAXHOSTNAMELEN + 1];

						GETSHORT(n, cp);

						memset(cname, '\0',
						       sizeof cname);
						(void) dn_expand(buf, eom, cp,
						                 cname,
						                 AR_MAXHOSTNAMELEN);
						q->q_depth--;
						ar_undot(cname);
						strlcpy(q->q_name, cname,
						        sizeof q->q_name);
						if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
						{
							syslog(LOG_DEBUG,
							       "arlib: %p reply was CNAME, requerying",
							       q);
						}
						ar_requery(lib, q);
						requeued = TRUE;
					}
				}
			}

			/* pack up the reply */
			if (q != NULL && !requeued)
			{
				pthread_mutex_lock(&q->q_lock);
				memcpy(q->q_buf, buf, MIN(r, q->q_buflen));
				q->q_flags |= QUERY_REPLY;
				q->q_replylen = r;
				if ((q->q_flags & QUERY_RESEND) != 0)
					lib->ar_resend--;
				if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				{
					syslog(LOG_DEBUG,
					       "arlib: %p signaling", q);
				}
				pthread_cond_signal(&q->q_reply);
				pthread_mutex_unlock(&q->q_lock);
			}
		}

		/* control socket messages (new work, resend requests) */
		if (ar_socket_check(lib->ar_dss, lib->ar_control[1],
		                    AR_SOCKET_EVENT_READ) == 1)
		{
			size_t rlen;
			AR_QUERY q;
			
			if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				syslog(LOG_DEBUG, "arlib: control socket");

			rlen = read(lib->ar_control[1], &q, sizeof q);
			if (rlen == 0)
			{
				pthread_mutex_unlock(&lib->ar_lock);
				return NULL;
			}

			/* specific resend request */
			if (q != NULL && (q->q_flags & QUERY_RESEND) == 0)
			{
				if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				{
					syslog(LOG_DEBUG,
					       "arlib: resend %p request", q);
				}

				q->q_flags |= QUERY_RESEND;
				lib->ar_resend++;
			}
		}

		/* take another run at any incomplete writev() we have going */
		if (lib->ar_nsfd != -1 &&
		    lib->ar_partwrite < lib->ar_fullwrite &&
		    ar_socket_check(lib->ar_dss, lib->ar_nsfd,
		                    AR_SOCKET_EVENT_WRITE) == 1)
		{
			int c;
			size_t n;
			struct iovec io[2];

			memcpy(&io, &lib->ar_iovec, sizeof io);
			n = lib->ar_partwrite;

			for (c = 0; c < 2; c++)
			{
				if (io[c].iov_len > (unsigned int) n)
				{
					io[c].iov_base = (char *) io[c].iov_base + n;
					io[c].iov_len -= n;
					break;
				}

				n -= (int) io[c].iov_len;
				io[c].iov_len = 0;
			}

			n = writev(lib->ar_nsfd, io, 2);
			if (n == -1)
			{
				/* request a reconnect */
	     			lib->ar_flags |= AR_FLAG_RECONNECT;

				/* arrange to re-send everything */
				ar_requeue(lib);
			}
			else
			{
				lib->ar_partwrite += n;
			}

			continue;
		}

		/* send any pending queries */
		if (lib->ar_nsfd != -1 &&
		    ar_socket_check(lib->ar_dss, lib->ar_nsfd,
		                    AR_SOCKET_EVENT_WRITE) == 1 &&
		    lib->ar_pending != NULL)
		{
			_Bool sent;

			/* reset read state if there's nothing outstanding */
			if (lib->ar_queries == NULL)
				lib->ar_tcpmsglen = 0;

			for (q = lib->ar_pending; q != NULL; q = q->q_next)
			{
				sent = FALSE;

				q = lib->ar_pending;

				lib->ar_pending = q->q_next;
				if (lib->ar_pending == NULL)
					lib->ar_pendingtail = NULL;

				q->q_next = NULL;

				/* make and write the query */
				pthread_mutex_lock(&q->q_lock);
				sent = ar_sendquery(lib, q);
				if (!sent)
				{
		     			lib->ar_flags |= AR_FLAG_RECONNECT;
					if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
					{
						syslog(LOG_DEBUG,
						       "arlib: send failed, requesting reconnect");
					}
				}
				pthread_mutex_unlock(&q->q_lock);

				if (sent)
				{
					/* add it to the active queries list */
					if (lib->ar_queriestail == NULL)
					{
						lib->ar_queries = q;
						lib->ar_queriestail = q;
					}
					else
					{
						lib->ar_queriestail->q_next = q;
						lib->ar_queriestail = q;
					}
				}

				ar_socket_reset(lib->ar_dss);
				ar_socket_add(lib->ar_dss, lib->ar_nsfd,
				              AR_SOCKET_EVENT_WRITE);

				status = ar_socket_wait(lib->ar_dss, 0);

				if (status != 1)
					break;
			}
		}

		/* send any queued resends */
		if (lib->ar_resend > 0 && lib->ar_nsfd != -1 &&
		    ar_socket_check(lib->ar_dss, lib->ar_nsfd,
		                    AR_SOCKET_EVENT_WRITE) == 1)
		{
			for (q = lib->ar_queries;
			     q != NULL && lib->ar_resend > 0;
			     q = q->q_next)
			{
				pthread_mutex_lock(&q->q_lock);
				if ((q->q_flags & QUERY_RESEND) != 0)
				{
					if (!ar_sendquery(lib, q))
		     				lib->ar_flags |= AR_FLAG_RECONNECT;
					q->q_flags &= ~QUERY_RESEND;
					lib->ar_resend--;
				}
				pthread_mutex_unlock(&q->q_lock);

				ar_socket_reset(lib->ar_dss);
				ar_socket_add(lib->ar_dss, lib->ar_nsfd,
				              AR_SOCKET_EVENT_WRITE);
				status = ar_socket_wait(lib->ar_dss, 0);
				if (status != 1)
					break;
			}
		}

		/* look through active queries for timeouts */
		for (q = lib->ar_queries; q != NULL; q = q->q_next)
		{
			pthread_mutex_lock(&q->q_lock);
			if ((q->q_flags & (QUERY_NOREPLY|QUERY_REPLY)) == 0 &&
			    ar_expired(q))
			{
				if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				{
					syslog(LOG_DEBUG, "arlib: expiring %p",
					       q);
				}
				q->q_flags |= QUERY_NOREPLY;
				pthread_cond_signal(&q->q_reply);
			}
			pthread_mutex_unlock(&q->q_lock);
		}

		/* look through what's left for retries */
		for (q = lib->ar_queries; q != NULL; q = q->q_next)
		{
			/* bail if ar_sendquery() would block */
			if (lib->ar_nsfd == -1)
				break;

			ar_socket_reset(lib->ar_dss);
			ar_socket_add(lib->ar_dss, lib->ar_nsfd,
			              AR_SOCKET_EVENT_WRITE);
			if (ar_socket_check(lib->ar_dss, lib->ar_nsfd,
			                    AR_SOCKET_EVENT_WRITE) != 1)
				break;

			pthread_mutex_lock(&q->q_lock);
			if (ar_elapsed(&q->q_sent, &lib->ar_retry))
			{
				if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
				{
					syslog(LOG_DEBUG, "arlib: retrying %p",
					       q);
				}

				if (!ar_sendquery(lib, q))
		     			lib->ar_flags |= AR_FLAG_RECONNECT;
			}
			pthread_mutex_unlock(&q->q_lock);
		}
	}

	return NULL;
}

/*
**  AR_RES_INIT -- res_init()/res_ninit() wrapper
**
**  Parameters:
**  	None.
**
**  Return value:
**  	0 on success, -1 on failure.
*/

static int
ar_res_init(AR_LIB new)
{
#if !defined(AR_RES_MANUAL) && !defined(AF_INET6)
	int c;
#endif /* !defined(AR_RES_MANUAL) && !defined(AF_INET6) */
	size_t bytes;
	SOCKADDR *sa;

	assert(new != NULL);

	h_errno = NETDB_SUCCESS;

	memset(&new->ar_res, '\0', sizeof new->ar_res);

	/*
	**  We'll trust that res_init()/res_ninit() will give us things
	**  like NS counts and retransmission times, but can't always rely
	**  on it for the nameservers.
	*/

#if (defined(__RES) && (__RES <= 19960801))
	/* old-school (bind4) */
	res_init();
	memcpy(&new->ar_res, &_res, sizeof new->ar_res);
#else /* defined(__RES) && (__RES <= 19960801) */
	/* new-school (bind8 and up) */
	(void) res_ninit(&new->ar_res);
#endif /* defined(__RES) && (__RES <= 19960801) */

	new->ar_nscount = new->ar_res.nscount;
	new->ar_retry.tv_sec = new->ar_res.retrans;
	new->ar_retry.tv_usec = 0;
	new->ar_retries = new->ar_res.retry;

	if (new->ar_nscount == 0)
		new->ar_nscount = MAXNS;

	bytes = sizeof(SOCKADDR) * new->ar_nscount;
	if (new->ar_malloc != NULL)
	{
		new->ar_nsaddrs = (SOCKADDR *) new->ar_malloc(new->ar_closure,
		                                              bytes);
	}
	else
	{
		new->ar_nsaddrs = (SOCKADDR *) malloc(bytes);
	}

	if (new->ar_nsaddrs == NULL)
		return -1;

	memset(new->ar_nsaddrs, '\0', sizeof(SOCKADDR) * new->ar_res.nscount);

#if defined(AR_RES_MANUAL) || defined(AF_INET6)
	ar_res_parse(&new->ar_nscount, new->ar_nsaddrs,
	             &new->ar_retries, &new->ar_retry.tv_sec);
#else /* defined(AR_RES_MANUAL) || defined(AF_INET6) */
	memcpy(new->ar_nsaddrs, &new->ar_res.nsaddr_list,
	       sizeof(SOCKADDR) * new->ar_res.nscount);

	/* an address of 0 (INADDR_ANY) should become INADDR_LOOPBACK */
	for (c = 0; c < new->ar_nscount; c++)
	{
		sa = (SOCKADDR *) &new->ar_nsaddrs[c];
		if (sa->sa_family == AF_INET)
		{
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *) sa;

			if (sin->sin_addr.s_addr == INADDR_ANY)
				sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		}
	}
#endif /* defined(AR_RES_MANUAL) || defined(AF_INET6) */

	return 0;
}

/*
**  ========================= PUBLIC FUNCTIONS =========================
*/

/*
**  AR_INIT -- instantiate the service
**
**  Parameters:
**  	user_malloc -- malloc() replacement function
**  	user_free -- free() replacement function
**  	user_closure -- memory closure to be used for library allocations
**  	flags -- flags
**
**  Return value:
**  	An AR_LIB handle on success, NULL on failure (check errno)
*/

AR_LIB
ar_init(ar_malloc_t user_malloc, ar_free_t user_free, void *user_closure,
        int flags)
{
	int status;
	int c;
	AR_LIB new;
	struct sockaddr *sa;

#define TMP_MALLOC(x)	(user_malloc == NULL ? malloc((x)) \
			                     : user_malloc(user_closure, ((x))));
#define TMP_FREE(x)	(user_free == NULL ? free((x)) \
			                   : user_free(user_closure, ((x))));
#define	TMP_CLOSE(x)	if ((x) != -1) \
				close((x));
				
	new = TMP_MALLOC(sizeof(struct ar_libhandle));
	if (new == NULL)
		return NULL;

	new->ar_dss = ar_socket_init(0);
	if (new->ar_dss == NULL)
	{
		free(new);
		return NULL;
	}

	new->ar_css = ar_socket_init(0);
	if (new->ar_css == NULL)
	{
		ar_socket_free(new->ar_dss);
		free(new);
		return NULL;
	}

	new->ar_malloc = user_malloc;
	new->ar_free = user_free;
	new->ar_closure = user_closure;
	new->ar_flags = flags;
	new->ar_drun = 0;
	new->ar_nsfd = -1;
	new->ar_nsfdpf = -1;
	new->ar_tcpbuflen = 0;
	new->ar_tcpmsglen = 0;
	new->ar_tcpbufidx = 0;
	new->ar_tcpbuf = NULL;
	new->ar_pending = NULL;
	new->ar_pendingtail = NULL;
	new->ar_queries = NULL;
	new->ar_queriestail = NULL;
	new->ar_recycle = NULL;
	new->ar_querybuflen = HFIXEDSZ + MAXPACKET;
	new->ar_control[0] = -1;
	new->ar_control[1] = -1;
	new->ar_nsidx = 0;
	new->ar_writelen = 0;
	new->ar_partwrite = 0;
	new->ar_fullwrite = 0;
	new->ar_deadsince.tv_sec = 0;
	new->ar_deadsince.tv_usec = 0;
	new->ar_revivify.tv_sec = AR_DEFREVIVIFY;
	new->ar_revivify.tv_usec = 0;

	if (ar_res_init(new) != 0)
	{
		TMP_FREE(new);
		return NULL;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, new->ar_control) != 0)
	{
		TMP_FREE(new);
		return NULL;
	}

	/* establish socket; connect if necessary */
	for (c = 0; c < new->ar_nscount; c++)
	{
		sa = (struct sockaddr *) &new->ar_nsaddrs[c];

		if ((new->ar_flags & AR_FLAG_USETCP) == 0)	/* UDP */
		{
			new->ar_nsfd = socket(sa->sa_family, SOCK_DGRAM, 0);
			if (new->ar_nsfd != -1)
			{
				new->ar_nsfdpf = sa->sa_family;
				break;
			}
		}
		else						/* TCP */
		{
			int socklen;

			new->ar_nsfd = socket(sa->sa_family, SOCK_STREAM, 0);
			if (new->ar_nsfd == -1)
				continue;
#ifdef AF_INET6
			if (sa->sa_family == AF_INET6)
				socklen = sizeof(struct sockaddr_in6);
			else
				socklen = sizeof(struct sockaddr_in);
#else /* AF_INET */
			socklen = sizeof(struct sockaddr_in);
#endif /* AF_INET */

			if (connect(new->ar_nsfd, sa, socklen) == 0)
			{
				new->ar_nsfdpf = sa->sa_family;
				break;
			}

			close(new->ar_nsfd);
			new->ar_nsfd = -1;
		}
	}

	if (new->ar_nsfd == -1)
	{
		TMP_CLOSE(new->ar_control[0]);
		TMP_CLOSE(new->ar_control[1]);
		TMP_FREE(new);
		return NULL;
	}

	new->ar_querybuf = TMP_MALLOC(new->ar_querybuflen);
	if (new->ar_querybuf == NULL)
	{
		TMP_CLOSE(new->ar_control[0]);
		TMP_CLOSE(new->ar_control[1]);
		TMP_CLOSE(new->ar_nsfd);
		TMP_FREE(new->ar_nsaddrs);
		TMP_FREE(new);
		return NULL;
	}

#ifdef ARDEBUG
	ar_debug_init();
#endif /* ARDEBUG */

	(void) pthread_mutex_init(&new->ar_lock, NULL);

	return new;
}

/*
**  AR_SHUTDOWN -- terminate an instance of the service
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	0 on success, or an errno on failure.
*/

int
ar_shutdown(AR_LIB lib)
{
	int status;

	assert(lib != NULL);

	close(lib->ar_control[0]);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: shutting down");

	status = 0;

	if (lib->ar_drun != 0)
		status = pthread_join(lib->ar_dispatcher, NULL);

	if (status == 0)
	{
		void *closure;
		void (*user_free)(void *, void *);

		close(lib->ar_nsfd);
		close(lib->ar_control[1]);
		pthread_mutex_destroy(&lib->ar_lock);

		ar_smashqueue(lib, lib->ar_pending);
		ar_smashqueue(lib, lib->ar_queries);
		ar_smashqueue(lib, lib->ar_recycle);

		if (lib->ar_tcpbuf != NULL)
			ar_free(lib, lib->ar_tcpbuf);
		ar_free(lib, lib->ar_querybuf);
		ar_free(lib, lib->ar_nsaddrs);

		closure = lib->ar_closure;
		user_free = lib->ar_free;

		ar_socket_free(lib->ar_css);
		ar_socket_free(lib->ar_dss);

		if (user_free != NULL)
			user_free(closure, lib);
		else
			free(lib);
	}

#ifdef ARDEBUG
	ar_debug_stop();
#endif /* ARDEBUG */

	return status;
}

/*
**  AR_SETRETRY -- set retry interval
**
**  Parameters:
**  	lib -- library handle
**  	new -- new retry interval (may be NULL);
**  	old -- current retry interval (returned; may be NULL)
**
**  Return value:
**  	None.
*/

void
ar_setretry(AR_LIB lib, struct timeval *new, struct timeval *old)
{
	assert(lib != NULL);

	if (old != NULL)
		memcpy(old, &lib->ar_retry, sizeof lib->ar_retry);

	if (new != NULL)
		memcpy(&lib->ar_retry, new, sizeof lib->ar_retry);
}

/*
**  AR_SETMAXRETRY -- set max retry count
**
**  Parameters:
**  	lib -- library handle
**  	new -- new value (or -1 to leave unchanged)
**  	old -- current value (returned; may be NULL)
**
**  Return value:
**  	None.
*/

void
ar_setmaxretry(AR_LIB lib, int new, int *old)
{
	assert(lib != NULL);

	if (old != NULL)
		*old = lib->ar_retries;

	if (new != -1)
		lib->ar_retries = new;
}

/*
**  AR_POKE -- poke the dispatcher
**
**  Parameters:
**  	lib -- AR library handle
**
**  Return value:
**  	Bytes written to the dispatcher control socket (i.e. the return from
**  	write(2)).
**
**  Notes:
**  	Write a four-byte NULL to the control descriptor to indicate
**  	to the dispatcher there's general work to do.  This will cause
**  	it to check its "pending" list for work to do and dispatch it.
**  	If the descriptor is not writeable, we don't much care because
**  	that means the pipe is full of messages already which will wake
**  	up the dispatcher anyway.
*/

static size_t
ar_poke(AR_LIB lib)
{
	int maxfd;
	int status;
	size_t wlen;
	AR_QUERY x = NULL;

	assert(lib != NULL);

	wlen = sizeof x;

	ar_socket_reset(lib->ar_css);
	ar_socket_add(lib->ar_css, lib->ar_control[0], AR_SOCKET_EVENT_WRITE);
	status = ar_socket_wait(lib->ar_css, 0);
	if (status == 1)
		wlen = write(lib->ar_control[0], &x, sizeof x);
	else if (status == -1)
		wlen = (size_t) -1;

	return wlen;
}

/*
**  AR_ADDQUERY -- add a query for processing
**
**  Parameters:
**  	lib -- library handle
**  	name -- name of the query to be submitted
**  	class -- class of the query to be submitted
**  	type -- type of the query to be submitted
**  	depth -- chase CNAMEs to this depth (0 == don't)
**  	buf -- buffer into which to write the result
**  	buflen -- bytes available at "buf"
**  	err -- pointer to an int which should receive errno on send errors
**  	timeout -- timeout (or NULL)
**
**  Return value:
**  	NULL -- error; see errno and/or the value returned in err
**  	otherwise, an AR_QUERY handle
*/

AR_QUERY
ar_addquery(AR_LIB lib, char *name, int class, int type, int depth,
            unsigned char *buf, size_t buflen, int *err,
            struct timeval *timeout)
{
	char prev;
	int status;
	size_t wlen;
	AR_QUERY q;
	char *p;

	assert(lib != NULL);
	assert(name != NULL);

	/*
	**  Sanity-check the name.  Look for invalid characters or patterns
	**  that will make res_mkquery() return -1 for reasons other than
	**  "buffer too short".
	**
	**  In particular, look for:
	**  	- non-ASCII characters
	**  	- non-printable characters
	**  	- things that start with "."
	**  	- things that contain adjacent "."s
	*/

	wlen = 0;
	prev = '\0';
	for (p = name; *p != '\0'; p++)
	{
		if (!isascii(*p) || !isprint(*p) ||
		    (*p == '.' && (prev == '.' || prev == '\0')))
		{
			if (err != NULL)
				*err = EINVAL;
			errno = EINVAL;
			return NULL;
		}

		prev = *p;
	}

	/* sanity-check the timeout, if provided */
	if (timeout != NULL)
	{
		if (timeout->tv_sec < 0 || timeout->tv_sec > AR_MAXTIMEOUT ||
		    timeout->tv_usec < 0 || timeout->tv_usec >= 1000000)
		{
			if (err != NULL)
				*err = EINVAL;
			errno = EINVAL;
			return NULL;
		}
	}

	pthread_mutex_lock(&lib->ar_lock);

	/* start the dispatcher if it's not already running */
	if (lib->ar_drun == 0)
	{
		status = pthread_create(&lib->ar_dispatcher, NULL,
		                        ar_dispatcher, lib);
		if (status != 0)
		{
			if (err != NULL)
				*err = status;
			errno = status;
			pthread_mutex_unlock(&lib->ar_lock);
			return NULL;
		}

		lib->ar_drun = 1;
	}

	if ((lib->ar_flags & AR_FLAG_DEAD) != 0)
	{
		if (err != NULL)
			*err = lib->ar_deaderrno;
		errno = lib->ar_deaderrno;
		pthread_mutex_unlock(&lib->ar_lock);
		return NULL;
	}

	if (lib->ar_recycle != NULL)
	{
		q = lib->ar_recycle;
		lib->ar_recycle = q->q_next;
		pthread_mutex_unlock(&lib->ar_lock);
	}
	else
	{
		pthread_mutex_unlock(&lib->ar_lock);
		q = ar_malloc(lib, sizeof(struct ar_query));
		if (q == NULL)
		{
			if (err != NULL)
				*err = errno;
			return NULL;
		}
		memset(q, '\0', sizeof(struct ar_query));
		pthread_mutex_init(&q->q_lock, NULL);
		pthread_cond_init(&q->q_reply, NULL);
	}

	/* construct the query */
	q->q_class = class;
	q->q_type = type;
	q->q_flags = 0;
	q->q_depth = depth;
	q->q_errno = err;
	q->q_next = NULL;
	q->q_buf = buf;
	q->q_buflen = buflen;
	q->q_tries = 0;
	if (timeout == NULL)
	{
		q->q_flags |= QUERY_INFINIWAIT;
		q->q_timeout.tv_sec = 0;
		q->q_timeout.tv_usec = 0;
	}
	else
	{
		(void) gettimeofday(&q->q_timeout, NULL);
		q->q_timeout.tv_sec += timeout->tv_sec;
		q->q_timeout.tv_usec += timeout->tv_usec;
		if (q->q_timeout.tv_usec >= 1000000)
		{
			q->q_timeout.tv_sec += 1;
			q->q_timeout.tv_usec -= 1000000;
		}
	}
	strlcpy(q->q_name, name, sizeof q->q_name);

	/* enqueue the query and signal the dispatcher */
	pthread_mutex_lock(&lib->ar_lock);
	if (lib->ar_pending == NULL)
	{
		lib->ar_pending = q;
		lib->ar_pendingtail = q;
	}
	else
	{
		lib->ar_pendingtail->q_next = q;
		lib->ar_pendingtail = q;
	}

	wlen = ar_poke(lib);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
	{
		syslog(LOG_DEBUG, "arlib: added query %p %d/%d '%s'",
		       q, q->q_class, q->q_type, q->q_name);
	}

	pthread_mutex_unlock(&lib->ar_lock);

	switch (wlen)
	{
	  case sizeof q:
		return q;

	  default:
		ar_recycle(lib, q);
		return NULL;
	}
}

/*
**  AR_CANCELQUERY -- cancel a pending query
**
**  Parameters:
**  	lib -- library handle
**  	query -- AR_QUERY handle which should be terminated
**
**  Return value:
**  	0 -- cancel successful
**  	1 -- cancel not successful (record not found)
*/

int
ar_cancelquery(AR_LIB lib, AR_QUERY query)
{
	AR_QUERY q;
	AR_QUERY last;

	assert(lib != NULL);
	assert(query != NULL);

	pthread_mutex_lock(&lib->ar_lock);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: canceling query %p", query);

	/* first, look in pending queries */
	for (q = lib->ar_pending, last = NULL;
	     q != NULL;
	     last = q, q = q->q_next)
	{
		if (query == q)
		{
			if (last == NULL)
			{
				lib->ar_pending = q->q_next;
				if (lib->ar_pending == NULL)
					lib->ar_pendingtail = NULL;
			}
			else
			{
				last->q_next = q->q_next;
				if (lib->ar_pendingtail == q)
					lib->ar_pendingtail = last;
			}

			q->q_next = lib->ar_recycle;
			if ((q->q_flags & QUERY_RESEND) != 0)
				lib->ar_resend--;
			lib->ar_recycle = q;

			pthread_mutex_unlock(&lib->ar_lock);
			return 0;
		}
	}
	
	/* next, look in active queries */
	for (q = lib->ar_queries, last = NULL;
	     q != NULL;
	     last = q, q = q->q_next)
	{
		if (query == q)
		{
			if (last == NULL)
			{
				lib->ar_queries = q->q_next;
				if (lib->ar_queries == NULL)
					lib->ar_queriestail = NULL;

			}
			else
			{
				last->q_next = q->q_next;
				if (lib->ar_queriestail == q)
					lib->ar_queriestail = last;
			}

			q->q_next = lib->ar_recycle;
			if ((q->q_flags & QUERY_RESEND) != 0)
				lib->ar_resend--;
			lib->ar_recycle = q;

			pthread_mutex_unlock(&lib->ar_lock);
			return 0;
		}
	}

	pthread_mutex_unlock(&lib->ar_lock);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: cancel failed for query %p", query);

	return 1;
}

/*
**  AR_WAITREPLY -- go to sleep waiting for a reply
**
**  Parameters:
**  	lib -- library handle
**  	query -- AR_QUERY handle of interest
**  	len -- length of the received reply (returned)
**  	timeout -- timeout for the wait, or NULL to wait for the query
**  	           to time out
**
**  Return value:
**  	AR_STAT_SUCCESS -- success; reply available
**  	AR_STAT_NOREPLY -- timeout; no reply available yet
**  	AR_STAT_EXPIRED -- timeout; query expired
**  	AR_STAT_ERROR -- error; see errno
**
**  Notes:
**  	If *len is greater than the size of the buffer provided when
**  	ar_addquery() was called, then there was some data truncated
**  	because the buffer was not big enough to receive the whole reply.
**  	The caller should resubmit with a larger buffer.
*/

int
ar_waitreply(AR_LIB lib, AR_QUERY query, size_t *len, struct timeval *timeout)
{
	_Bool infinite;
	_Bool maintimeout = FALSE;
	int status;
	struct timespec until;
	struct timeval now;

	assert(lib != NULL);
	assert(query != NULL);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: waiting for query %p", query);

	pthread_mutex_lock(&query->q_lock);

	if ((query->q_flags & QUERY_REPLY) != 0)
	{
		if (len != NULL)
			*len = query->q_replylen;
		pthread_mutex_unlock(&query->q_lock);

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: wait for %p successful",
			       query);
		}

		return AR_STAT_SUCCESS;
	}
	else if ((query->q_flags & QUERY_ERROR) != 0)
	{
		pthread_mutex_unlock(&query->q_lock);

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: wait for %p error [1]",
			       query);
		}

		return AR_STAT_ERROR;
	}
	else if ((query->q_flags & QUERY_NOREPLY) != 0)
	{
		if (query->q_errno != NULL)
			*query->q_errno = ETIMEDOUT;
		pthread_mutex_unlock(&query->q_lock);

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: wait for %p expired",
			       query);
		}

		return AR_STAT_EXPIRED;
	}

	/*
	**  Pick the soonest of:
	**  - timeout specified above
	**  - timeout specified on the query
	**  - forever
	*/

	(void) gettimeofday(&now, NULL);
	infinite = FALSE;
	until.tv_sec = 0;
	until.tv_nsec = 0;

	if (timeout == NULL && (query->q_flags & QUERY_INFINIWAIT) != 0)
	{
		infinite = TRUE;
	}
	else
	{
		/* if a timeout was specified above */
		if (timeout != NULL)
		{
			until.tv_sec = now.tv_sec + timeout->tv_sec;
			until.tv_nsec = now.tv_usec + timeout->tv_usec;
			if (until.tv_nsec >= 1000000)
			{
				until.tv_sec += 1;
				until.tv_nsec -= 1000000;
			}
			until.tv_nsec *= 1000;
		}

		/* if a timeout was specified on the query */
		if ((query->q_flags & QUERY_INFINIWAIT) == 0)
		{
			if (until.tv_sec == 0 ||
			    until.tv_sec > query->q_timeout.tv_sec ||
			    (until.tv_sec == query->q_timeout.tv_sec &&
			     until.tv_nsec > query->q_timeout.tv_usec * 1000))
			{
				until.tv_sec = query->q_timeout.tv_sec;
				until.tv_nsec = query->q_timeout.tv_usec * 1000;
				maintimeout = TRUE;
			}
		}
	}

	while ((query->q_flags & (QUERY_REPLY|QUERY_NOREPLY|QUERY_ERROR)) == 0)
	{
		if (infinite)
		{
			status = pthread_cond_wait(&query->q_reply,
			                           &query->q_lock);
		}
		else
		{
			status = pthread_cond_timedwait(&query->q_reply,
			                                &query->q_lock,
			                                &until);
			if (status == ETIMEDOUT)
				break;
		}
	}

	/* recheck flags */
	if ((query->q_flags & QUERY_ERROR) != 0)
	{
		pthread_mutex_unlock(&query->q_lock);

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: wait for %p error [2]",
			       query);
		}

		return AR_STAT_ERROR;
	}
	else if ((query->q_flags & QUERY_REPLY) == 0)
	{
		if (maintimeout && query->q_errno != NULL)
			*query->q_errno = ETIMEDOUT;
		pthread_mutex_unlock(&query->q_lock);

		if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		{
			syslog(LOG_DEBUG, "arlib: wait for %p timeout (%s)",
			       query, maintimeout ? "expired" : "no reply");
		}

		return (maintimeout ? AR_STAT_EXPIRED : AR_STAT_NOREPLY);
	}

	if (len != NULL)
		*len = query->q_replylen;
	pthread_mutex_unlock(&query->q_lock);

	if ((lib->ar_flags & AR_FLAG_TRACELOGGING) != 0)
		syslog(LOG_DEBUG, "arlib: wait for %p succeeded", query);

	return AR_STAT_SUCCESS;
}

/*
**  AR_RECYCLE -- recycle a query when the caller is done with it
**
**  Parameters:
**  	lib -- library handle
**  	query -- AR_QUERY handle to recycle
**
**  Return value:
**  	None.
*/

void
ar_recycle(AR_LIB lib, AR_QUERY query)
{
	assert(lib != NULL);
	assert(query != NULL);

	pthread_mutex_lock(&lib->ar_lock);
	query->q_next = lib->ar_recycle;
	lib->ar_recycle = query;
	pthread_mutex_unlock(&lib->ar_lock);
}

/*
**  AR_RESEND -- enqueue re-sending of a pending request
**
**  Parameters:
**  	lib -- library handle
**  	query -- query to re-send
**
**  Return value:
**  	0 on success, -1 on failure.
*/

int
ar_resend(AR_LIB lib, AR_QUERY query)
{
	size_t wlen;

	assert(lib != NULL);
	assert(query != NULL);

	wlen = write(lib->ar_control[1], query, sizeof query);
	return (wlen == 4 ? 0 : -1);
}

/*
**  AR_STRERROR -- translate an error code
**
**  Parameters:
**  	err -- error code
**
**  Return value:
**  	Pointer to a text string which represents that error code.
*/

char *
ar_strerror(int err)
{
	switch (err)
	{
	  case QUERY_ERRNO_RETRIES:
		return "Too many retries";

	  case QUERY_ERRNO_TOOBIG:
		return "Unable to construct query";

	  default:
		return strerror(errno);
	}
}

/*
**  AR_RESOLVCONF -- parse a resolv.conf file for nameservers to use
**
**  Parameters:
**  	ar -- AR_LIB handle to update
**  	file -- path to access
**
**  Return value:
**  	0 -- success
**  	!0 -- an error occurred; check errno
**
**  Notes:
**  	Parse errors are not reported.
**
**  	The default set is not modified if no "nameserver" lines are found.
*/

int
ar_resolvconf(AR_LIB ar, char *file)
{
	int af;
	int n = 0;
	FILE *f;
	char *p;
	char *sp;
	SOCKADDR *news;
	struct sockaddr_in s4;
#ifdef AF_INET6
	struct sockaddr_in6 s6;
#endif /* AF_INET6 */
	char buf[BUFRSZ];

	assert(ar != NULL);
	assert(file != NULL);

	f = fopen(file, "r");
	if (f == NULL)
		return -1;

	memset(buf, '\0', sizeof buf);

	while (fgets(buf, sizeof buf - 1, f) != NULL)
	{
		sp = NULL;

		for (p = buf; *p != '\0'; p++)
		{
			if (sp == NULL && isspace(*p))
				sp = p;

			if (*p == '#' || *p == '\n')
			{
				*p = '\0';
				break;
			}
		}

		if (sp != NULL)
			*sp = '\0';

		if (strcasecmp(buf, "nameserver") != 0)
			continue;

		af = -1;
		if (inet_pton(AF_INET, sp + 1, &s4.sin_addr.s_addr) == 0)
			af = AF_INET;
#ifdef AF_INET6
		else if (inet_pton(AF_INET6, sp + 1,
		         &s6.sin6_addr.s6_addr) == 0)
			af = AF_INET6;
#endif /* AF_INET6 */

		if (af == -1)
			continue;

		if (n == 0)
		{
			news = (SOCKADDR *) malloc(MAXNS * sizeof(SOCKADDR));
			if (news == NULL)
			{
				fclose(f);
				return -1;
			}

			free(ar->ar_nsaddrs);
			ar->ar_nsaddrs = news;
		}

		if (af == AF_INET)
		{
			s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			s4.sin_len = sizeof s4;
#endif /* HAVE_SIN_LEN */
			memcpy(&news[n], &s4, sizeof s4);
		}
#ifdef AF_INET6
		else if (af == AF_INET6)
		{
			s6.sin6_family = AF_INET6;
# ifdef HAVE_SIN6_LEN
			s6.sin6_len = sizeof s6;
# endif /* HAVE_SIN6_LEN */
			memcpy(&news[n], &s6, sizeof s6);
		}
#endif /* AF_INET6 */

		n++;
		if (n == MAXNS)
			break;
	}

	ar->ar_nscount = n;

	fclose(f);

	return 0;
}
