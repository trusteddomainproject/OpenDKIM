/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2014, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <resolv.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

#define	BUFRSZ		1024
#define	MAXADDRESS	256
#define	MAXHEADER	4096

#ifndef MIN
# define MIN(x,y)	((x) < (y) ? (x) : (y))
#endif /* ! MIN */

#define SIG2 "v=1;  a=rsa-sha1; c=simple/simple; d=example.com; s=test;\r\n\tt=1172620939; r=y; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Message-ID;\r\n\tb=F/cSOK/4qujIeNhKcC1LjAMFS33ORcsRqoEfNO6g1WXMlK5LW/foFePbUyFbbEbhY\r\n\t 8RhU+7C4R914QI6WW+lYMh11p0z1BGu2HJ4HHOlBivi1DDfZgsRZrEJhBeMngNIN9+\r\n\t 8HbGhTSWWpOBn+jYtfvGJBGtbv3AjgVgNropc7DM="

size_t alen;
unsigned char *abuf;
unsigned char qbuf[BUFRSZ];

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
	alen = buflen;
	strlcpy(qbuf, query, sizeof qbuf);

	return DKIM_DNS_SUCCESS;
}

static int
stub_dns_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                   int *error, int *dnssec)
{
	unsigned char *cp;
	unsigned char *eom;
	int elen;
	int slen;
	int olen;
	char *q;
	unsigned char *len;
	unsigned char *dnptrs[3];
	unsigned char **lastdnptr;
	HEADER newhdr;

	memset(&newhdr, '\0', sizeof newhdr);
	memset(&dnptrs, '\0', sizeof dnptrs);
		
	newhdr.qdcount = htons(1);
	newhdr.ancount = htons(1);
	newhdr.rcode = NOERROR;
	newhdr.opcode = QUERY;
	newhdr.qr = 1;
	newhdr.id = 0;

	lastdnptr = &dnptrs[2];
	dnptrs[0] = abuf;

	/* copy out the new header */
	memcpy(abuf, &newhdr, sizeof newhdr);

	cp = &abuf[HFIXEDSZ];
	eom = &abuf[alen];

	/* question section */
	elen = dn_comp(qbuf, cp, eom - cp, dnptrs, lastdnptr);
	if (elen == -1)
		return DKIM_DNS_ERROR;
	cp += elen;
	PUTSHORT(T_TXT, cp);
	PUTSHORT(C_IN, cp);

	/* answer section */
	elen = dn_comp(qbuf, cp, eom - cp, dnptrs, lastdnptr);
	if (elen == -1)
		return DKIM_DNS_ERROR;
	cp += elen;
	PUTSHORT(T_TXT, cp);
	PUTSHORT(C_IN, cp);
	PUTLONG(0L, cp);

	len = cp;
	cp += INT16SZ;

	slen = strlen(REPORTRECORD);
	q = REPORTRECORD;
	olen = 0;

	while (slen > 0)
	{
		elen = MIN(slen, 255);
		*cp = (char) elen;
		cp++;
		olen++;
		memcpy(cp, q, elen);
		q += elen;
		cp += elen;
		olen += elen;
		slen -= elen;
	}

	eom = cp;

	cp = len;
	PUTSHORT(olen, cp);

	*bytes = eom - abuf;

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
	int hfd;
	int bfd;
	u_int flags;
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_LIB *lib;
	DKIM_SIGINFO *sig;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	unsigned char hdr[MAXHEADER + 1];
	unsigned char addr[MAXADDRESS + 1];
	unsigned char opts[BUFRSZ];
	unsigned char smtp[BUFRSZ];

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	if (!dkim_libfeature(lib, DKIM_FEATURE_SHA256))
	{
		printf("*** simple/simple rsa-sha256 verifying with extra signature spaces and reportinfo (failure) SKIPPED\n");
		dkim_close(lib);
		return 0;
	}

	printf("*** simple/simple rsa-sha256 verifying with extra signature spaces and reportinfo (failure)\n");

	/* DNS stubs for the reporting data lookup */
	dkim_dns_set_query_service(lib, NULL);
	dkim_dns_set_query_start(lib, stub_dns_query);
	dkim_dns_set_query_cancel(lib, stub_dns_cancel);
	dkim_dns_set_query_waitreply(lib, stub_dns_waitreply);

	/* set flags */
	flags = DKIM_LIBFLAGS_TMPFILES;
#ifdef TEST_KEEP_FILES
	flags |= DKIM_LIBFLAGS_KEEPFILES;
#endif /* TEST_KEEP_FILES */
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
	                    &qtype, sizeof qtype);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
	                    KEYFILE, strlen(KEYFILE));

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
	assert(status == DKIM_STAT_BADSIG);

	/* set up for the rest */
	hfd = -1;
	bfd = -1;
	sig = dkim_getsignature(dkim);
	assert(sig != NULL);

	/* request report info, verify valid descriptors and address */
	memset(addr, '\0', sizeof addr);
	memset(opts, '\0', sizeof opts);
	memset(smtp, '\0', sizeof smtp);
	status = dkim_sig_getreportinfo(dkim, sig, &hfd, &bfd,
	                                addr, sizeof addr,
	                                opts, sizeof opts,
	                                smtp, sizeof smtp, NULL);
	assert(status == DKIM_STAT_OK);
	assert(hfd > 2);
	assert(bfd > 2);
	assert(strcmp(addr, REPLYADDRESS) == 0);
	assert(strcmp(smtp, SMTPTOKEN) == 0);

	/* test descriptors */
	status = lseek(hfd, 0, SEEK_CUR);
	assert(status >= 0);
	status = lseek(bfd, 0, SEEK_CUR);
	assert(status >= 0);

	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
