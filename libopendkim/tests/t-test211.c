/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, 2026, The Trusted Domain Project.
**  	All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096
#define	MAXPACKET	8192

#define	SIG2 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="

/*
**  Best-effort replacement for the byte beyond the DNS message.  The
**  vulnerable copy loop reads this as the remainder of an overlong TXT
**  character-string; it parses as a key with an unsupported version, which
**  is a different result than the syntax error the fixed parser returns.
*/

#define	OOBPAYLOAD	"v=DKIM2; k=rsa; p=AAAA"

static unsigned char *abuf;
static size_t abuflen;
static unsigned char qbuf[256];

static int
stub_dns_init(void **srv)
{
	*srv = (void *) 0x01;
	return 0;
}

static void
stub_dns_close(void *srv)
{
}

static int
stub_dns_cancel(void *srv, void *q)
{
	return DKIM_DNS_SUCCESS;
}

static int
stub_dns_query(void *srv, int type, unsigned char *query,
               unsigned char *buf, size_t buflen, void **qh)
{
	abuf = buf;
	abuflen = buflen;
	snprintf((char *) qbuf, sizeof qbuf, "%s", (char *) query);

	return DKIM_DNS_SUCCESS;
}

static int
stub_dns_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                   int *error, int *dnssec)
{
	unsigned char *cp;
	unsigned char *eom;
	unsigned char *msgend;
	unsigned char *rdlen;
	HEADER hdr;
	int n;

	memset(&hdr, '\0', sizeof hdr);
	hdr.qdcount = htons(1);
	hdr.ancount = htons(1);
	hdr.rcode = NOERROR;
	hdr.opcode = QUERY;
	hdr.qr = 1;

	memset(abuf, '\0', abuflen);
	memcpy(abuf, &hdr, sizeof hdr);

	cp = abuf + HFIXEDSZ;
	eom = abuf + abuflen;

	/* question section */
	n = dn_comp((char *) qbuf, cp, eom - cp, NULL, NULL);
	if (n < 0)
		return DKIM_DNS_ERROR;
	cp += n;
	PUTSHORT(T_TXT, cp);
	PUTSHORT(C_IN, cp);

	/* answer section */
	n = dn_comp((char *) qbuf, cp, eom - cp, NULL, NULL);
	if (n < 0)
		return DKIM_DNS_ERROR;
	cp += n;
	PUTSHORT(T_TXT, cp);
	PUTSHORT(C_IN, cp);
	PUTLONG(0L, cp);

	rdlen = cp;
	cp += INT16SZ;

	/*
	**  A single character-string whose length byte claims 255 bytes while
	**  RDLENGTH provides none.  The DNS message ends immediately after
	**  that byte; the payload below sits past eom but inside the answer
	**  buffer, so a parser that follows the lying length byte reads it.
	*/

	*cp++ = 0xff;
	msgend = cp;
	PUTSHORT(1, rdlen);

	memcpy(msgend, OOBPAYLOAD, sizeof OOBPAYLOAD - 1);

	*bytes = msgend - abuf;

	if (dnssec != NULL)
		*dnssec = DKIM_DNSSEC_UNKNOWN;

	return DKIM_DNS_SUCCESS;
}

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
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	unsigned char hdr[MAXHEADER + 1];

	printf("*** overlong TXT character-string is rejected\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	/* replace the resolver with one that returns a crafted answer */
	dkim_dns_set_query_service(lib, NULL);
	dkim_dns_set_init(lib, stub_dns_init);
	dkim_dns_set_close(lib, stub_dns_close);
	dkim_dns_set_query_start(lib, stub_dns_query);
	dkim_dns_set_query_cancel(lib, stub_dns_cancel);
	dkim_dns_set_query_waitreply(lib, stub_dns_waitreply);

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	snprintf(hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	status = dkim_header(dkim, hdr, strlen(hdr));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER01, strlen(HEADER01));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER02, strlen(HEADER02));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER03, strlen(HEADER03));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER04, strlen(HEADER04));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER08, strlen(HEADER08));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER09, strlen(HEADER09));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY00, strlen(BODY00));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY01, strlen(BODY01));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY01A, strlen(BODY01A));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01B, strlen(BODY01B));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01C, strlen(BODY01C));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01D, strlen(BODY01D));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01E, strlen(BODY01E));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY02, strlen(BODY02));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY04, strlen(BODY04));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY05, strlen(BODY05));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_CANTVRFY);

	sig = dkim_getsignature(dkim);
	assert(sig != NULL);
	assert(dkim_sig_geterror(sig) == DKIM_SIGERROR_DNSSYNTAX);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
