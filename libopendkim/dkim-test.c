/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012-2014, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <resolv.h>
#include <errno.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#else /* USE_GNUTLS */
/* openssl includes */
# include <openssl/bio.h>
# include <openssl/rsa.h>
# include <openssl/evp.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-types.h"
#include "dkim-keys.h"
#include "dkim-util.h"
#include "dkim-test.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* definitions */
#define	TESTTTL			300
#define MAXPACKET		8192

/* prototypes from elsewhere */
extern DKIM_STAT dkim_get_key __P((DKIM *, DKIM_SIGINFO *, _Bool));

/*
**  DKIM_TEST_DNS_PUT -- enqueue a DNS reply for automated testing
**
**  Parameters:
**  	dkim -- DKIM handle
**  	class -- class of the reply
**  	type -- type of the reply
**  	prec -- precedence (for MX replies)
**  	name -- name of the reply (i.e. the "question")
**  	data -- content of the reply
**
**  Return value:
**  	0 -- success
**  	-1 -- failure (e.g. malloc() failed)
*/

int
dkim_test_dns_put(DKIM *dkim, int class, int type, int prec, u_char *name,
                  u_char *data)
{
	struct dkim_test_dns_data *td;

	assert(dkim != NULL);
	assert(name != NULL);

	td = (struct dkim_test_dns_data *) DKIM_MALLOC(dkim, sizeof *td);
	if (td == NULL)
		return -1;

	td->dns_class = class;
	td->dns_type = type;
	td->dns_prec = prec;

	td->dns_query = dkim_strdup(dkim, name, 0);
	if (td->dns_query == NULL)
	{
		DKIM_FREE(dkim, td);
		return -1;
	}

	if (data != NULL)
	{
		td->dns_reply = dkim_strdup(dkim, data, 0);
		if (td->dns_reply == NULL)
		{
			DKIM_FREE(dkim, td->dns_query);
			DKIM_FREE(dkim, td);
			return -1;
		}
	}

	td->dns_next = NULL;

	if (dkim->dkim_dnstesth == NULL)
		dkim->dkim_dnstesth = td;
	else
		dkim->dkim_dnstestt->dns_next = td;

	dkim->dkim_dnstestt = td;

	return 0;
}

/*
**  DKIM_TEST_DNS_GET -- dequeue a DNS reply for automated testing
**
**  Parameters:
**  	dkim -- DKIM handle
**  	buf -- target buffer
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	-1 -- nothing queued
**  	other -- size of the reply
*/

size_t
dkim_test_dns_get(DKIM *dkim, u_char *buf, size_t buflen)
{
	int n;
	int len;
	uint32_t testttl;
	struct dkim_test_dns_data *td;
	u_char *cp;
	u_char *p;
	u_char *end;
	u_char answer[MAXPACKET];
	HEADER hdr;

	td = dkim->dkim_dnstesth;
	if (td == NULL)
		return -1;

	dkim->dkim_dnstesth = td->dns_next;

	/* encode the reply */
	memset(&hdr, '\0', sizeof hdr);
	hdr.qdcount = htons(1);
	hdr.rcode = (td->dns_reply == NULL ? NXDOMAIN : NOERROR);
	hdr.ancount = (td->dns_reply == NULL ? htons(0) : htons(1));

	memcpy(answer, &hdr, sizeof hdr);

	cp = answer + HFIXEDSZ;
	end = answer + sizeof answer;

	/* repeat the question */
	n = dn_comp((char *) td->dns_query, cp, end - cp, NULL, NULL);
	if (n < 0)
	{
		DKIM_FREE(dkim, td);
		return -1;
	}
	cp += n;
	if (end - cp < 2 * sizeof(uint16_t))
	{
		DKIM_FREE(dkim, td);
		return -1;
	}

	PUTSHORT(td->dns_type, cp);
	PUTSHORT(td->dns_class, cp);

	/* short-circuit? */
	if (hdr.rcode == NXDOMAIN)
	{
		DKIM_FREE(dkim, td);

		memcpy(buf, answer, buflen);

		return cp - answer;
	}

	/* the answer starts out the same way */
	n = dn_comp((char *) td->dns_query, cp, end - cp, NULL, NULL);
	if (n < 0)
	{
		DKIM_FREE(dkim, td);
		return -1;
	}
	cp += n;

	if (end - cp < 2 * sizeof(uint16_t) + sizeof(uint32_t))
	{
		DKIM_FREE(dkim, td);
		return -1;
	}

	PUTSHORT(td->dns_type, cp);
	PUTSHORT(td->dns_class, cp);

	testttl = htonl(TESTTTL);
	PUTLONG(testttl, cp);

	switch (td->dns_type)
	{
	  case T_TXT:
		/* figure out how many bytes we need total */
		n = strlen((char *) td->dns_reply);
		len = n + n / 255 + 1;
		if (end - cp < len + sizeof(uint16_t))
		{
			DKIM_FREE(dkim, td);
			return -1;
		}
		PUTSHORT(len, cp);

		/* write the buffer, inserting length bytes as needed */
		len = 0;
		p = td->dns_reply;
		while (n > 0)
		{
			if (len == 0)
			{
				len = MIN(255, n);
				*cp++ = len;
			}
			*cp++ = *p++;
			n--;
			len--;
		}
		break;

	  case T_MX:
		if (end - cp < sizeof(uint16_t))
		{
			DKIM_FREE(dkim, td);
			return -1;
		}
		PUTSHORT(td->dns_prec, cp);
		n = dn_comp((char *) td->dns_reply, cp, end - cp, NULL, NULL);
		if (n < 0)
		{
			DKIM_FREE(dkim, td);
			return -1;
		}

		cp += n;
		break;

	  default:
		DKIM_FREE(dkim, td);
		return -1;
	}

	DKIM_FREE(dkim, td);

	memcpy(buf, answer, buflen);

	return cp - answer;
}

/*
**  DKIM_TEST_KEY -- retrieve a public key and verify it against a provided
**                   private key
**
**  Parameters:
**  	lib -- DKIM library handle
**  	selector -- selector
**  	domain -- domain name
**  	key -- private key to verify (PEM format)
**  	keylen -- size of private key
**  	dnssec -- DNSSEC result (may be NULL)
**  	err -- error buffer (may be NULL)
**  	errlen -- size of error buffer
**
**  Return value:
**  	1 -- keys don't match
**  	0 -- keys match (or no key provided)
**  	-1 -- error
*/

int
dkim_test_key(DKIM_LIB *lib, char *selector, char *domain,
              char *key, size_t keylen, int *dnssec, char *err, size_t errlen)
{
	int status = 0;
	DKIM_STAT stat;
	DKIM *dkim;
	DKIM_SIGINFO *sig;
#ifdef USE_GNUTLS
	gnutls_datum_t keybuf;
	gnutls_datum_t outkey;
#else /* USE_GNUTLS */
	BIO *keybuf;
	BIO *outkey;
#endif /* USE_GNUTLS */
	void *ptr;
	struct dkim_crypto *crypto;
	char buf[BUFRSZ];

	assert(lib != NULL);
	assert(selector != NULL);
	assert(domain != NULL);

	dkim = dkim_verify(lib, (u_char *) "test", NULL, &stat);
	if (dkim == NULL)
	{
		if (err != NULL)
			strlcpy(err, dkim_getresultstr(stat), errlen);
		return -1;
	}

	snprintf(buf, sizeof buf, "v=1; d=%s; s=%s; h=x; b=x; a=x",
	         domain, selector);

	stat = dkim_process_set(dkim, DKIM_SETTYPE_SIGNATURE, (u_char *) buf,
	                        strlen(buf), NULL, FALSE, NULL);
	if (stat != DKIM_STAT_OK)
	{
		strlcpy(err, "syntax error on input", errlen);
		(void) dkim_free(dkim);
		return -1;
	}

	dkim->dkim_sigcount = 1;

	stat = dkim_siglist_setup(dkim);
	if (stat != DKIM_STAT_OK)
	{
		(void) dkim_free(dkim);
		return -1;
	}

	sig = dkim->dkim_siglist[0];

	dkim->dkim_user = dkim_strdup(dkim, (u_char *) "nobody", 0);
	if (dkim->dkim_user == NULL)
	{
		(void) dkim_free(dkim);
		return -1;
	}

	stat = dkim_get_key(dkim, sig, TRUE);
	if (stat != DKIM_STAT_OK)
	{
		if (err != NULL)
		{
			const char *errstr;

			errstr = dkim_geterror(dkim);
			if (errstr != NULL)
			{
				strlcpy(err, errstr, errlen);
			}
			else
			{
				strlcpy(err, dkim_getresultstr(stat),
				        errlen);
			}
		}

		(void) dkim_free(dkim);
		return -1;
	}

	if (dnssec != NULL)
		*dnssec = dkim_sig_getdnssec(sig);

	if (key != NULL)
	{
		crypto = DKIM_MALLOC(dkim, sizeof(struct dkim_crypto));
		if (crypto == NULL)
		{
			(void) dkim_free(dkim);
			if (err != NULL)
			{
				snprintf(err, errlen,
				         "unable to allocate %zu byte(s)",
				         sizeof(struct dkim_crypto));
			}
			return -1;
		}
		memset(crypto, '\0', sizeof(struct dkim_crypto));

#ifdef USE_GNUTLS
		keybuf.data = key;
		keybuf.size = keylen;
#else /* USE_GNUTLS */
		keybuf = BIO_new_mem_buf(key, keylen);
		if (keybuf == NULL)
		{
			if (err != NULL)
			{
				strlcpy(err, "BIO_new_mem_buf() failed",
				        errlen);
			}

			(void) dkim_free(dkim);
			return -1;
		}
#endif /* USE_GNUTLS */

		sig->sig_signature = (void *) crypto;
		sig->sig_keytype = DKIM_KEYTYPE_RSA;

#ifdef USE_GNUTLS
		if (err != NULL)
			strlcpy(err, "function not implemented", errlen);

		(void) dkim_free(dkim);
		return -1;
#else /* USE_GNUTLS */
		crypto->crypto_pkey = PEM_read_bio_PrivateKey(keybuf, NULL,
		                                              NULL, NULL);
		if (crypto->crypto_pkey == NULL)
		{
			BIO_free(keybuf);
			(void) dkim_free(dkim);
			if (err != NULL)
			{
				strlcpy(err,
				        "PEM_read_bio_PrivateKey() failed",
				        errlen);
			}
			return -1;
		}

		crypto->crypto_key = EVP_PKEY_get1_RSA(crypto->crypto_pkey);
		if (crypto->crypto_key == NULL)
		{
			BIO_free(keybuf);
			(void) dkim_free(dkim);
			if (err != NULL)
			{
				strlcpy(err, "EVP_PKEY_get1_RSA() failed",
				        errlen);
			}
			return -1;
		}
	
		crypto->crypto_keysize = RSA_size(crypto->crypto_key);
		crypto->crypto_pad = RSA_PKCS1_PADDING;

		outkey = BIO_new(BIO_s_mem());
		if (outkey == NULL)
		{
			BIO_free(keybuf);
			(void) dkim_free(dkim);
			if (err != NULL)
				strlcpy(err, "BIO_new() failed", errlen);
			return -1;
		}

		status = i2d_RSA_PUBKEY_bio(outkey, crypto->crypto_key);
		if (status == 0)
		{
			BIO_free(keybuf);
			BIO_free(outkey);
			(void) dkim_free(dkim);
			if (err != NULL)
			{
				strlcpy(err, "i2d_RSA_PUBKEY_bio() failed",
				        errlen);
			}
			return -1;
		}

		(void) BIO_get_mem_data(outkey, &ptr);

		if (BIO_number_written(outkey) == sig->sig_keylen)
			status = memcmp(ptr, sig->sig_key, sig->sig_keylen);
		else
			status = 1;

		if (status != 0)
			strlcpy(err, "keys do not match", errlen);

		BIO_free(keybuf);
		BIO_free(outkey);
#endif /* USE_GNUTLS */
	}

	(void) dkim_free(dkim);

	return (status == 0 ? 0 : 1);
}
