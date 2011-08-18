/*
**  Copyright (c) 2010, 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char ar_test00_c_id[] = "@(#)$Id: ar-test00.c,v 1.2 2010/08/30 22:01:56 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* libar includes */
#include "../async-resolv.h"

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

#define	AR_MAXHOSTNAMELEN	256

#define	TESTQUERY		"yahoo.com"

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	The usual.
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	int err = NOERROR;
	int n;
	size_t len;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t type;
	uint16_t class;
	uint16_t rrsize;
	uint32_t ttl;
	uint32_t addr;
	AR_LIB ar;
	AR_QUERY q;
	HEADER *hdr;
	unsigned char *cp;
	unsigned char *eom;
	struct timeval timeout;
	unsigned char name[AR_MAXHOSTNAMELEN + 1];
	unsigned char buf[MAXPACKET];

	printf("*** simple A query\n");

	/* initialize */
	ar = ar_init(NULL, NULL, NULL, 0);
	assert(ar != NULL);

	/* launch a query */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	q = ar_addquery(ar, TESTQUERY, C_IN, T_A, 0, buf, sizeof buf, &err,
	                &timeout);
	assert(q != NULL);

	/* wait for the reply */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	assert(ar_waitreply(ar, q, &len, &timeout) == AR_STAT_SUCCESS);
	assert(len <= sizeof buf);
	assert(err == NOERROR);

	/* verify it */
	hdr = (HEADER *) buf;
	cp = buf + HFIXEDSZ;
	eom = buf + len;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr->qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		memset(name, '\0', sizeof name);
		(void) dn_expand((unsigned char *) buf, eom, cp,
		                 (RES_UNC_T) name, sizeof name);

		assert(strcasecmp(name, TESTQUERY) == 0);

		n = dn_skipname(cp, eom);
		assert(n > 0);
		cp += n;

		/* extract the type and class */
		GETSHORT(type, cp);
		assert(type == T_A);
		GETSHORT(class, cp);
		assert(class == C_IN);
	}

	assert(hdr->rcode == NOERROR);

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr->ancount);
	assert(ancount != 0);

	printf("--- got %u answer(s)\n", ancount);

	while (ancount-- > 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		memset(name, '\0', sizeof name);
		n = dn_expand((unsigned char *) buf, eom, cp,
		              (RES_UNC_T) name, sizeof name);
		assert(n > 0);
		assert(strcasecmp(name, TESTQUERY) == 0);
		
		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		assert(cp + INT16SZ + INT16SZ + INT32SZ <= eom);
		GETSHORT(type, cp);
		assert(type == T_A);
		GETSHORT(class, cp);
		assert(class == C_IN);
		GETLONG(ttl, cp);
		assert(ttl >= 0);

		/* get payload length */
		assert(cp + INT16SZ <= eom);
		GETSHORT(n, cp);

		/* extract payload */
		assert(cp + INT32SZ <= eom);
		GETLONG(addr, cp);

		/* output it */
		addr = ntohl(addr);
		printf("--- '%s' has address %02u.%02u.%02u.%02u\n",
		       TESTQUERY,
		       (addr & 0x000000ff),
		       (addr & 0x0000ff00) >> 8,
		       (addr & 0x00ff0000) >> 16,
		       (addr & 0xff000000) >> 24);
	}

	/* free memory */
	ar_cancelquery(ar, q);

	/* shut down */
	assert(ar_shutdown(ar) == 0);

	return 0;
}
