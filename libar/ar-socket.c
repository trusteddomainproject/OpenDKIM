/*
**  Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
*/

/* OS stuff */
#if HPUX11
# define _XOPEN_SOURCE_EXTENDED
#endif /* HPUX11 */

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#ifdef POLL
# include <poll.h>
#else /* POLL */
# include <sys/select.h>
#endif /* POLL */
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

/* libar includes */
#include "ar-socket.h"

/* useful stuff */
#ifndef NULL
# define NULL	0
#endif /* ! NULL */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */

#define	MINSETSIZE	16

/* data types */
struct ar_socket_set
{
#ifdef POLL
	unsigned int	arss_alloc;
	unsigned int	arss_num;
	struct pollfd *	arss_poll;
#else /* POLL */
	int		arss_maxfd;
	fd_set		arss_rfds;
	fd_set		arss_wfds;
	fd_set		arss_xfds;
#endif /* POLL */
};

/*
**  AR_SOCKET_INIT -- create a socket set
**
**  Parameters:
**  	initsz -- initial set size
**
**  Return value:
**  	A newly-allocated socket set handle, or NULL on error.
*/

AR_SOCKET_SET
ar_socket_init(unsigned int initsz)
{
	struct ar_socket_set *new;

	new = (AR_SOCKET_SET) malloc(sizeof *new);
	if (new == NULL)
		return NULL;

	if (initsz < MINSETSIZE)
		initsz = MINSETSIZE;

#ifdef POLL
	new->arss_poll = (struct pollfd *) malloc(sizeof(struct pollfd) * initsz);
	if (new->arss_poll == NULL)
	{
		free(new);
		return NULL;
	}

	new->arss_num = 0;
	new->arss_alloc = initsz;
#else /* POLL */
	new->arss_maxfd = -1;
	FD_ZERO(&new->arss_rfds);
	FD_ZERO(&new->arss_wfds);
	FD_ZERO(&new->arss_xfds);
#endif /* POLL */

	return new;
}

/*
**  AR_SOCKET_FREE -- release a socket set
**
**  Parameters:
**  	ss -- AR_SOCKET_SET to be released
**
**  Return value:
**  	None.
*/

void
ar_socket_free(AR_SOCKET_SET ss)
{
	assert(ss != NULL);

#ifdef POLL
	if (ss->arss_poll != NULL)
		free(ss->arss_poll);
#endif /* POLL */

	free(ss);
}

/*
**  AR_SOCKET_RESET -- reset a socket set
**
**  Parameters:
**  	ss -- AR_SOCKET_SET to be reset
**
**  Return value:
**  	None.
*/

void
ar_socket_reset(AR_SOCKET_SET ss)
{
	assert(ss != NULL);

#ifdef POLL
	ss->arss_num = 0;
#else /* POLL */
	ss->arss_maxfd = -1;
	FD_ZERO(&ss->arss_rfds);
	FD_ZERO(&ss->arss_wfds);
	FD_ZERO(&ss->arss_xfds);
#endif /* POLL */
}

/*
**  AR_SOCKET_ADD -- add a socket of interest to the socket set
**
**  Parameters:
**  	ss -- socket set
**  	fd -- descriptor
**  	events -- bitmask of events of interest
**
**  Return value:
**  	-1 -- error (check errno)
**  	0 -- success
*/

int
ar_socket_add(AR_SOCKET_SET ss, int fd, unsigned int events)
{
#ifdef POLL
	int c;
#endif /* POLL */

	assert(ss != NULL);
	assert(fd >= 0);

#ifdef POLL
	/* if this one is alerady in the set, update the events bitmask */
	for (c = 0; c < ss->arss_num; c++)
	{
		if (ss->arss_poll[c].fd == fd)
		{
			if ((events & AR_SOCKET_EVENT_READ) != 0)
				ss->arss_poll[c].events |= POLLIN;
			if ((events & AR_SOCKET_EVENT_WRITE) != 0)
				ss->arss_poll[c].events |= POLLOUT;
			if ((events & AR_SOCKET_EVENT_EXCEPTION) != 0)
				ss->arss_poll[c].events |= (POLLERR|POLLHUP|POLLNVAL);

			return 0;
		}
	}

	/* adding; resize poll array if needed */
	if (ss->arss_alloc == ss->arss_num)
	{
		unsigned int new;
		struct pollfd *newp;

		new = ss->arss_alloc * 2;
		newp = (struct pollfd *) realloc(ss->arss_poll,
		                                 new * sizeof(struct pollfd));
		if (newp == NULL)
			return -1;

		ss->arss_alloc = new;
		ss->arss_poll = newp;
	}

	ss->arss_poll[ss->arss_num].fd = fd;
	ss->arss_poll[ss->arss_num].events = 0;
	ss->arss_poll[ss->arss_num].revents = 0;
	if ((events & AR_SOCKET_EVENT_READ) != 0)
		ss->arss_poll[ss->arss_num].events |= POLLIN;
	if ((events & AR_SOCKET_EVENT_WRITE) != 0)
		ss->arss_poll[ss->arss_num].events |= POLLOUT;
	if ((events & AR_SOCKET_EVENT_EXCEPTION) != 0)
		ss->arss_poll[ss->arss_num].events |= (POLLERR|POLLHUP|POLLNVAL);
	ss->arss_num++;

	return 0;
#else /* POLL */
	if (fd >= FD_SETSIZE)
	{
		errno = EINVAL;
		return -1;
	}

	if ((events & AR_SOCKET_EVENT_READ) != 0)
		FD_SET(fd, &ss->arss_rfds);
	if ((events & AR_SOCKET_EVENT_WRITE) != 0)
		FD_SET(fd, &ss->arss_wfds);
	if ((events & AR_SOCKET_EVENT_EXCEPTION) != 0)
		FD_SET(fd, &ss->arss_xfds);

	if (fd > ss->arss_maxfd)
		ss->arss_maxfd = fd;

	return 0;
#endif /* POLL */
}

/*
**  AR_SOCKET_CHECK -- see if a socket has particular events set after waiting
**
**  Parameters:
**  	ss -- socket set
**  	fd -- descriptor of interest
**  	events -- events of interest
**
**  Return value:
**  	1 -- one or more of the requested socket events occurred
**  	0 -- none of the requested socket events occurred
**  	-1 -- an error occurred
*/

int
ar_socket_check(AR_SOCKET_SET ss, int fd, unsigned int events)
{
#ifdef POLL
	unsigned int c;
#else /* POLL */
	int ret;
#endif /* POLL */

	assert(ss != NULL);
	assert(fd >= 0);

#ifdef POLL
	for (c = 0; c < ss->arss_num; c++)
	{
		if (ss->arss_poll[c].fd == fd)
		{
			/* read */
			if ((events & AR_SOCKET_EVENT_READ) != 0 &&
			    (ss->arss_poll[c].revents & POLLIN) != 0)
				return 1;

			/* write */
			if ((events & AR_SOCKET_EVENT_WRITE) != 0 &&
			    (ss->arss_poll[c].revents & POLLOUT) != 0)
				return 1;

			/* exception */
			if ((events & AR_SOCKET_EVENT_EXCEPTION) != 0 &&
			    (ss->arss_poll[c].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0)
				return 1;

			return 0;
		}
	}

	return 0;
#else /* POLL */
	if (fd >= FD_SETSIZE)
	{
		errno = EINVAL;
		return -1;
	}

	ret = 0;
	if ((events & AR_SOCKET_EVENT_READ) != 0 &&
	    FD_ISSET(fd, &ss->arss_rfds))
		ret = 1;
	if ((events & AR_SOCKET_EVENT_WRITE) != 0 &&
	    FD_ISSET(fd, &ss->arss_wfds))
		ret = 1;
	if ((events & AR_SOCKET_EVENT_EXCEPTION) != 0 &&
	    FD_ISSET(fd, &ss->arss_xfds))
		ret = 1;

	return ret;
#endif /* POLL */
}

/*
**  AR_SOCKET_WAIT -- wait for a socket in a set to become ready
**
**  Parameters:
**  	ss -- socket set
**  	timeout -- time (in milliseconds) to wait; -1 = forever
**
**  Return value:
**  	Number of descriptors that are ready; 0 = timeout, -1 = error
*/

int
ar_socket_wait(AR_SOCKET_SET ss, int timeout)
{
#ifndef POLL
	struct timeval to;
#endif /* POLL */

	assert(ss != NULL);

#ifdef POLL
	return poll(ss->arss_poll, ss->arss_num, timeout);
#else /* POLL */
	if (timeout != -1)
	{
		to.tv_sec = timeout / 1000;
		to.tv_usec = (timeout % 1000) * 1000;
	}

	return select(ss->arss_maxfd + 1,
	              &ss->arss_rfds,
	              &ss->arss_wfds,
	              &ss->arss_xfds,
	              timeout == -1 ? NULL : &to);
#endif /* POLL */
}
