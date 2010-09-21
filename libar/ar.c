/*
**  Copyright (c) 2004-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char ar_c_id[] = "@(#)$Id: ar.c,v 1.9 2010/09/21 17:43:10 cm-msk Exp $";
#endif /* !lint */

/* OS stuff */
#if HPUX11
# define _XOPEN_SOURCE_EXTENDED
#endif /* HPUX11 */

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
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <signal.h>
#include <string.h>

/* important macros */
#define AR_MAXHOSTNAMELEN	256

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

#if !POLL && !KQUEUES
# define SELECT			1
# define READ_READY(x, y)	FD_ISSET((y), &(x))
#endif /* !POLL && !KQUEUES */

#ifndef MSG_WAITALL
# define MSG_WAITALL	0
#endif /* ! MSG_WAITALL */

#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

/* ar includes */
#include "ar.h"
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
	int			ar_nsfd;
	int			ar_nsfdpf;
	int			ar_control[2];
	int			ar_flags;
	int			ar_nscount;
	int			ar_nsidx;
	int			ar_deaderrno;
	int			ar_resend;
	int			ar_retries;
	size_t			ar_tcpbuflen;
	size_t			ar_writelen;
	size_t			ar_querybuflen;
	pthread_t		ar_dispatcher;
	pthread_mutex_t		ar_lock;
	unsigned char *		ar_querybuf;
	unsigned char *		ar_tcpbuf;
	SOCKADDR *		ar_nsaddrs;
	void *			(*ar_malloc) (void *closure, size_t nbytes);
	void			(*ar_free) (void *closure, void *p);
	void *			ar_closure;
	struct ar_query *	ar_pending;	/* to be sent (queue head) */
	struct ar_query *	ar_pendingtail;	/* to be sent (queue tail) */
	struct ar_query *	ar_queries;	/* awaiting replies (head) */
	struct ar_query *	ar_queriestail;	/* awaiting replies (tail) */
	struct ar_query *	ar_recycle;	/* recyclable queries */
	struct timeval		ar_retry;	/* retry interval */
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
**  ========================= PRIVATE FUNCTIONS =========================
*/

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
	if (tmp.tv_usec > 1000000)
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
		q->q_flags |= (QUERY_NOREPLY|QUERY_ERROR);
		pthread_cond_signal(&q->q_reply);
		pthread_mutex_unlock(&q->q_lock);
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
**  	Assumes the caller does not currently hold ar_lock.
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

	close(lib->ar_nsfd);
	lib->ar_nsfd = -1;
	lib->ar_nsfdpf = -1;

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
			continue;

		lib->ar_nsfdpf = sa->sa_family;

		if (connect(lib->ar_nsfd, sa, socklen) == 0)
			return TRUE;

		close(lib->ar_nsfd);
		lib->ar_nsfd = -1;
		lib->ar_nsfdpf = -1;
	}

	saveerrno = errno;

	/* unable to reconnect; arrange to terminate */
	pthread_mutex_lock(&lib->ar_lock);
	ar_alldead(lib);
	lib->ar_flags |= AR_FLAG_DEAD;
	lib->ar_deaderrno = saveerrno;
	pthread_mutex_unlock(&lib->ar_lock);

	return FALSE;
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

	if (lib->ar_queries != NULL)
	{
		int maxfd;
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

#if SELECT
		/* XXX -- do this as ar_trywrite() or something */
		maxfd = lib->ar_control[0];
		FD_ZERO(&wfds);
		FD_SET(lib->ar_control[0], &wfds);
		stimeout.tv_sec = 0;
		stimeout.tv_usec = 0;
		status = select(maxfd + 1, NULL, &wfds, NULL, &stimeout);
		if (status == 1)
			(void) write(lib->ar_control[0], &x, sizeof x);
#endif /* SELECT */
	}
}

/*
**  AR_SENDQUERY -- send a query
**
**  Parameters:
**  	lib -- library handle
**  	query -- query to send
**
**  Return value:
**  	None.
*/

static void
ar_sendquery(AR_LIB lib, AR_QUERY query)
{
	size_t n;
	HEADER hdr;

	assert(lib != NULL);
	assert(query != NULL);

	if (lib->ar_retries > 0 && query->q_tries == lib->ar_retries)
	{
		query->q_flags |= QUERY_ERROR;
		if (query->q_errno != NULL)
			*query->q_errno = QUERY_ERRNO_RETRIES;
		pthread_cond_signal(&query->q_reply);
		return;
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
			return;
		}

		ar_free(lib, lib->ar_querybuf);
		lib->ar_querybuflen *= 2;
		lib->ar_querybuf = ar_malloc(lib, lib->ar_querybuflen);
	}

	memcpy(&hdr, lib->ar_querybuf, sizeof hdr);
	query->q_id = hdr.id;

#ifdef DEBUG
	printf("*** SEND `%s' class=%d type=%d id=%d time=%d\n", query->q_name,
	       query->q_class, query->q_type, hdr.id, time(NULL));
#endif /* DEBUG */

	/* send it */
	if ((lib->ar_flags & AR_FLAG_USETCP) != 0)
	{
		u_short len;
		struct iovec io[2];

		len = htons(n);
		io[0].iov_base = (void *) &len;
		io[0].iov_len = sizeof len;
		io[1].iov_base = (void *) lib->ar_querybuf;
		io[1].iov_len = lib->ar_writelen;

		n = writev(lib->ar_nsfd, io, 2);
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
	}

	if (n == (size_t) -1)
	{
		query->q_flags |= QUERY_REPLY;
		if (query->q_errno != NULL)
			*query->q_errno = errno;
		pthread_cond_signal(&query->q_reply);
	}

	query->q_tries += 1;
	(void) gettimeofday(&query->q_sent, NULL);
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
	_Bool wrote;
	_Bool usetimeout;
	int status;
	int maxfd;
	AR_LIB lib;
	AR_QUERY q;
#if SELECT
	fd_set rfds;
	fd_set wfds;
#endif /* SELECT */
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

	for (;;)
	{
		maxfd = MAX(lib->ar_nsfd, lib->ar_control[1]);

		/* check on the control descriptor and the NS descriptor */
#if SELECT
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (lib->ar_pending != NULL || lib->ar_resend > 0)
			FD_SET(lib->ar_nsfd, &wfds);
		FD_SET(lib->ar_nsfd, &rfds);
		FD_SET(lib->ar_control[1], &rfds);

		/* determine how long to wait */
		timeout.tv_sec = AR_MAXTIMEOUT;
		timeout.tv_usec = 0;
		usetimeout = (lib->ar_queries != NULL);
		for (q = lib->ar_queries; q != NULL; q = q->q_next)
		{
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

		/* XXX -- effect a poll if we knew there was more pending */
		status = select(maxfd + 1, &rfds, &wfds, NULL,
		                usetimeout ? &timeout : NULL);
		if (status == -1)
		{
			if (errno == EINTR)
				continue;
			else
				assert(status >= 0);
		}

		pthread_mutex_lock(&lib->ar_lock);
#endif /* SELECT */

		wrote = FALSE;

		/* read what's available for dispatch */
		if (READ_READY(rfds, lib->ar_nsfd))
		{
			_Bool requeued = FALSE;
			size_t r;
			u_char *buf;
			HEADER hdr;

			if ((lib->ar_flags & AR_FLAG_USETCP) == 0)
			{
				r = recvfrom(lib->ar_nsfd, lib->ar_querybuf,
				             lib->ar_querybuflen, 0, NULL,
				             NULL);
				if (r == (size_t) -1)
					continue;

				buf = lib->ar_querybuf;
			}
			else
			{
				u_short len;
				_Bool err = FALSE;
				int part;
				unsigned char *where;

				/* first get the length */
				len = 0;
				r = recvfrom(lib->ar_nsfd, &len, sizeof len,
				             MSG_WAITALL, NULL, NULL);
				if (r == (size_t) -1)
				{
					if (errno == EINTR)
						continue;
					else
						err = TRUE;
				}
				else if (r == 0)
				{
					err = TRUE;
				}
				else if (r < sizeof len)
				{
					continue;
				}

				if (err)
				{
					/* reconnect */
					pthread_mutex_unlock(&lib->ar_lock);
					if (!ar_reconnect(lib))
						return NULL;
					pthread_mutex_lock(&lib->ar_lock);

					/* arrange to re-send everything */
					ar_requeue(lib);

					continue;
				}

				len = ntohs(len);

				/* allocate a buffer */
				if (lib->ar_tcpbuf == NULL ||
				    lib->ar_tcpbuflen < len)
				{
					if (lib->ar_tcpbuf != NULL)
					{
						ar_free(lib, lib->ar_tcpbuf);
						lib->ar_tcpbuf = NULL;
					}

					lib->ar_tcpbuf = ar_malloc(lib, len);
					lib->ar_tcpbuflen = len;
				}

				/*
				**  XXX -- improve multiplexing here by making
				**  this its own case
				*/

				/* grab the reply (maybe in pieces) */
				r = 0;
				where = lib->ar_tcpbuf;
				while (len > 0)
				{
					part = recvfrom(lib->ar_nsfd,
					                where, len, 0,
					                NULL, NULL);
					if (part == 0 || part == (size_t) -1)
					{
						if (errno == EINTR)
							continue;

						err = TRUE;
						break;
					}

					r += part;
					len -= part;
					where += part;
				}

				if (err)
				{
					/* reconnect */
					pthread_mutex_unlock(&lib->ar_lock);
					if (!ar_reconnect(lib))
						return NULL;
					pthread_mutex_lock(&lib->ar_lock);

					/* arrange to re-send everything */
					ar_requeue(lib);

					continue;
				}

				buf = lib->ar_tcpbuf;
			}

			/* truncate extra data */
			if (r > MAXPACKET)
				r = MAXPACKET;

			memcpy(&hdr, buf, sizeof hdr);

			/* check for truncation in UDP mode */
			if (hdr.rcode == NOERROR && hdr.tc &&
			    (lib->ar_flags & AR_FLAG_USETCP) == 0 &&
			    ((lib->ar_flags & AR_FLAG_TRUNCCHECK) == 0 ||
			     ar_anscount(buf, r) == 0))
			{
				lib->ar_flags |= AR_FLAG_USETCP;

				/* reconnect */
				pthread_mutex_unlock(&lib->ar_lock);
				if (!ar_reconnect(lib))
					return NULL;
				pthread_mutex_lock(&lib->ar_lock);

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
						break;
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
				pthread_cond_signal(&q->q_reply);
				pthread_mutex_unlock(&q->q_lock);
				if ((q->q_flags & QUERY_RESEND) != 0)
					lib->ar_resend--;
			}
		}

		/* send a pending query */
		if (READ_READY(wfds, lib->ar_nsfd) && lib->ar_pending != NULL)
		{
			q = lib->ar_pending;

			lib->ar_pending = q->q_next;
			if (lib->ar_pending == NULL)
				lib->ar_pendingtail = NULL;

			q->q_next = NULL;

			/* make and write the query */
			pthread_mutex_lock(&q->q_lock);
			ar_sendquery(lib, q);
			pthread_mutex_unlock(&q->q_lock);
			wrote = TRUE;
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

		/* pending resends */
		if (!wrote && lib->ar_resend > 0 &&
		    READ_READY(wfds, lib->ar_nsfd))
		{
			for (q = lib->ar_queries;
			     !wrote && q != NULL && lib->ar_resend > 0;
			     q = q->q_next)
			{
				pthread_mutex_lock(&q->q_lock);
				if ((q->q_flags & QUERY_RESEND) != 0)
				{
					ar_sendquery(lib, q);
					q->q_flags &= ~QUERY_RESEND;
					wrote = TRUE;
					lib->ar_resend--;
				}
				pthread_mutex_unlock(&q->q_lock);
			}
		}

		/* control socket messages */
		if (READ_READY(rfds, lib->ar_control[1]))
		{
			size_t rlen;
			AR_QUERY q;
			
			rlen = read(lib->ar_control[1], &q, sizeof q);
			if (rlen == 0)
			{
				pthread_mutex_unlock(&lib->ar_lock);
				return NULL;
			}

			/* resend request */
			if (q != NULL && (q->q_flags & QUERY_RESEND) == 0)
			{
				q->q_flags |= QUERY_RESEND;
				lib->ar_resend++;
			}
		}

		/* look through active queries for timeouts */
		for (q = lib->ar_queries; q != NULL; q = q->q_next)
		{
			pthread_mutex_lock(&q->q_lock);
			if ((q->q_flags & (QUERY_NOREPLY|QUERY_REPLY)) == 0 &&
			    ar_expired(q))
			{
				q->q_flags |= QUERY_NOREPLY;
				pthread_cond_signal(&q->q_reply);
			}
			pthread_mutex_unlock(&q->q_lock);
		}

		/* look through what's left for retries */
		for (q = lib->ar_queries; q != NULL; q = q->q_next)
		{
			pthread_mutex_lock(&q->q_lock);
			if (ar_elapsed(&q->q_sent, &lib->ar_retry))
			{
				if ((lib->ar_flags & AR_FLAG_USETCP) == 0)
				{
					ar_sendquery(lib, q);
				}
				else
				{
					lib->ar_nsidx = (lib->ar_nsidx + 1) % lib->ar_nscount;

					/* reconnect */
					pthread_mutex_unlock(&lib->ar_lock);
					if (!ar_reconnect(lib))
						return NULL;
					pthread_mutex_lock(&lib->ar_lock);

					/* arrange to re-send everything */
					ar_requeue(lib);
				}

				pthread_mutex_unlock(&q->q_lock);

				break;
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

	new->ar_malloc = user_malloc;
	new->ar_free = user_free;
	new->ar_closure = user_closure;
	new->ar_flags = flags;
	new->ar_nsfd = -1;
	new->ar_nsfdpf = -1;
	new->ar_tcpbuflen = 0;
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

	(void) pthread_mutex_init(&new->ar_lock, NULL);

	status = pthread_create(&new->ar_dispatcher, NULL, ar_dispatcher, new);
	if (status != 0)
	{
		TMP_CLOSE(new->ar_control[0]);
		TMP_CLOSE(new->ar_control[1]);
		TMP_CLOSE(new->ar_nsfd);

		TMP_FREE(new->ar_querybuf);
		TMP_FREE(new->ar_nsaddrs);
		TMP_FREE(new);

		return NULL;
	}

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

		if (user_free != NULL)
			user_free(closure, lib);
		else
			free(lib);
	}

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
	int maxfd;
	size_t wlen;
	AR_QUERY q;
	AR_QUERY x;
	char *p;
#if SELECT
	fd_set wfds;
	struct timeval stimeout;
#endif /* SELECT */

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
			errno = EINVAL;
			return NULL;
		}
	}

	pthread_mutex_lock(&lib->ar_lock);

	if ((lib->ar_flags & AR_FLAG_DEAD) != 0)
	{
		pthread_mutex_unlock(&lib->ar_lock);
		if (err != NULL)
			*err = lib->ar_deaderrno;
		errno = lib->ar_deaderrno;
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
	x = NULL;
	
	/*
	**  Write a four-byte NULL to the control descriptor to indicate
	**  to the dispatcher there's general work to do.  This will cause
	**  it to check its "pending" list for work to do and dispatch it.
	**  If the descriptor is not writeable, we don't much care because
	**  that means the pipe is full of messages already which will wake
	**  up the dispatcher anyway.
	*/

#if SELECT
	/* XXX -- do this as ar_trywrite() or something */
	maxfd = lib->ar_control[0];
	FD_ZERO(&wfds);
	FD_SET(lib->ar_control[0], &wfds);
	stimeout.tv_sec = 0;
	stimeout.tv_usec = 0;
	status = select(maxfd + 1, NULL, &wfds, NULL, &stimeout);
	if (status == 1)
	{
		wlen = write(lib->ar_control[0], &x, sizeof x);
	}
	else if (status == 0)
	{
		wlen = sizeof x;
	}
	else
	{
		if (err != NULL)
			*err = errno;
	}
#endif /* SELECT */

	pthread_mutex_unlock(&lib->ar_lock);

	switch (wlen)
	{
	  case sizeof x:
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

	pthread_mutex_lock(&query->q_lock);

	if ((query->q_flags & QUERY_REPLY) != 0)
	{
		if (len != NULL)
			*len = query->q_replylen;
		pthread_mutex_unlock(&query->q_lock);
		return AR_STAT_SUCCESS;
	}
	else if ((query->q_flags & QUERY_ERROR) != 0)
	{
		pthread_mutex_unlock(&query->q_lock);
		return AR_STAT_ERROR;
	}
	else if ((query->q_flags & QUERY_NOREPLY) != 0)
	{
		pthread_mutex_unlock(&query->q_lock);
		if (query->q_errno != NULL)
			*query->q_errno = ETIMEDOUT;
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
			if (until.tv_nsec > 1000000)
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

	while ((query->q_flags & (QUERY_REPLY|QUERY_NOREPLY)) == 0)
	{
		if (infinite == 1)
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
		errno = lib->ar_deaderrno;
		return AR_STAT_ERROR;
	}
	else if ((query->q_flags & QUERY_REPLY) == 0)
	{
		pthread_mutex_unlock(&query->q_lock);
		if (maintimeout && query->q_errno != NULL)
			*query->q_errno = ETIMEDOUT;
		return (maintimeout ? AR_STAT_EXPIRED : AR_STAT_NOREPLY);
	}

	pthread_mutex_unlock(&query->q_lock);
	if (len != NULL)
		*len = query->q_replylen;
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
