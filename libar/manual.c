/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, The OpenDKIM Project.  All rights reserved.
*/

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#ifdef DARWIN
# include <arpa/nameser.h>
#endif /* DARWIN */
#include <resolv.h>
#include <netdb.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <time.h>

/* macros */
#ifndef _PATH_RESCONF
# define _PATH_RESCONF	"/etc/resolv.conf"
#endif /* ! _PATH_RESCONF */
#ifndef RES_RETRY
# define RES_RETRY	4
#endif /* ! RES_RETRY */
#ifndef RES_TIMEOUT
# define RES_TIMEOUT	5
#endif /* ! RES_TIMEOUT */
#ifndef INADDR_NONE
# define INADDR_NONE	0xffffffff
#endif /* INADDR_NONE */

#define BUFRSZ		1024

#define	SERVICE		"domain"
#define	PROTOCOL	"udp"

/*
**  AR_RES_PARSE -- read resolv.conf and determine the nameservers
**
**  Parameters:
**  	nscount -- count of nameservers to load (in/out)
**  	out -- location of array to populate
**  	retry -- maximum retry count (returned)
**  	retrans -- retransmission timeout (returned)
**
**  Return value:
**  	0 on success, -1 on failure.
**
**  Notes:
**  	Includes IPv6 support if AF_INET6 is defined.  This presumes
**  	further that there's a "struct sockaddr_storage" defined
**  	in the system include files.  I haven't seen anything yet
**  	yet that guarantees this is a valid assumption, but
**  	so far so good...
*/

int
#ifdef AF_INET6
ar_res_parse(int *nscount, struct sockaddr_storage *out,
#else /* AF_INET6 */
ar_res_parse(int *nscount, struct sockaddr_in *out,
#endif /* AF_INET6 */
             int *retry, long *retrans)
{
	int data;
	int ns = 0;
	FILE *f;
	char *p;
	char *q;
	char *r;
	struct servent *srv;
	char buf[BUFRSZ];

	assert(out != NULL);
	assert(retry != NULL);
	assert(retrans != NULL);

	srv = getservbyname(SERVICE, PROTOCOL);
	if (srv == NULL)
		return -1;

	f = fopen(_PATH_RESCONF, "r");
	if (f == NULL)
	{
		struct sockaddr *sa;
		struct sockaddr_in *sin;

		/* apply defaults */
#ifdef AF_INET6
		sa = (struct sockaddr *) &out[0];
		sin = (struct sockaddr_in *) sa;
		sin->sin_family = AF_INET;
		sin->sin_port = srv->s_port;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#else /* AF_INET6 */
		out[0].sin_family = AF_INET;
		out[0].sin_port = srv->s_port;
		out[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#endif /* AF_INET6 */

		ns = 1;

		*nscount = ns;

		return 0;
	}

	clearerr(f);
	while (fgets(buf, sizeof buf, f) != NULL)
	{
		/* chomp at \n, #, or ; */
		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n' || *p == ';' || *p == '#')
			{
				*p = '\0';
				break;
			}
		}

		/* now eat leading and trailing spaces */
		data = 0;
		r = NULL;
		for (p = buf, q = buf; *p != '\0'; p++)
		{
			if (data == 0 && isascii(*p) && isspace(*p))
				continue;

			data = 1;
			*q = *p;
			if (!(isascii(*p) && isspace(*p)))
				r = q;
			q++;
		}
		if (r != NULL)
			*(r + 1) = '\0';

		/* use the data */
		if (strncasecmp(buf, "nameserver", 10) == 0)
		{
			struct in_addr addr;
#ifdef AF_INET6
			struct in6_addr addr6;
			struct sockaddr *sa;
			struct sockaddr_in *sin;
			struct sockaddr_in6 *sin6;
#endif /* AF_INET6 */

			for (p = &buf[10]; *p != '\0'; p++)
			{
				if (!isascii(*p) || !isspace(*p))
					break;
			}

			if (*p == '\0')
				continue;

#ifdef AF_INET6
			sa = (struct sockaddr *) &out[ns];
			if (inet_pton(AF_INET, p, (void *) &addr) == 1)
			{
				sin = (struct sockaddr_in *) sa;

				memcpy(&sin->sin_addr, &addr,
				       sizeof sin->sin_addr);
				sin->sin_family = AF_INET;
				sin->sin_port = srv->s_port;
				ns++;
			}
			else if (inet_pton(AF_INET6, p,
			                   (void *) &addr6.s6_addr) == 1)
			{
				sin6 = (struct sockaddr_in6 *) sa;

				memcpy(&sin6->sin6_addr, &addr6.s6_addr,
				       sizeof sin6->sin6_addr);
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = srv->s_port;
				ns++;
			}
#else /* AF_INET6 */
			addr.s_addr = inet_addr(p);
			if (addr.s_addr == INADDR_NONE)
				continue;

			memcpy(&out[ns].sin_addr.s_addr,
			       &addr.s_addr,
			       sizeof out[ns].sin_addr.s_addr);
			out[ns].sin_family = AF_INET;
			out[ns].sin_port = srv->s_port;

			ns++;
#endif /* AF_INET6 */
			if (ns == *nscount)
				break;
		}
	}

	fclose(f);

	*retry = RES_RETRY;
	*retrans = RES_TIMEOUT;

	/* if no "nameserver" lines were found, add a default one */
	if (ns == 0)
	{
#ifdef AF_INET6
		struct sockaddr *sa;
		struct sockaddr_in *sin;

		sa = (struct sockaddr *) &out[0];
		sin = (struct sockaddr_in *) sa;
		sin->sin_family = AF_INET;
		sin->sin_port = srv->s_port;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#else /* AF_INET6 */
		out[0].sin_family = AF_INET;
		out[0].sin_port = srv->s_port;
		out[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#endif /* AF_INET6 */

		ns = 1;
	}

	*nscount = ns;

	return 0;
}

#ifdef TEST
int
main()
{
	int c;
	struct sockaddr *sa;
	struct sockaddr_in *sin;
# ifdef AF_INET6
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage nsaddrs[MAXNS];
# else /* AF_INET6 */
	struct sockaddr_in nsaddrs[MAXNS];
# endif /* AF_INET6 */
	char buf[256];

	memset(nsaddrs, '\0', sizeof nsaddrs);

	ar_res_parse(MAXNS, (void *) nsaddrs);

	for (c = 0; c < MAXNS; c++)
	{
		memset(buf, '\0', sizeof buf);

		sa = (struct sockaddr *) &nsaddrs[c];

		switch (sa->sa_family)
		{
		  case AF_INET:
			sin = (struct sockaddr_in *) &nsaddrs[c];
			printf("IPv4: %s:%u\n", inet_ntop(AF_INET,
			       (void *) &sin->sin_addr, buf, sizeof buf),
			       ntohs(sin->sin_port));
			break;

# ifdef AF_INET6
		  case AF_INET6:
			sin6 = (struct sockaddr_in6 *) &nsaddrs[c];
			printf("IPv6: %s:%u\n", inet_ntop(AF_INET6,
			       (void *) &sin6->sin6_addr, buf, sizeof buf),
			       ntohs(sin6->sin6_port));
			break;
		}
# endif /* AF_INET6 */
	}
}
#endif /* TEST */
