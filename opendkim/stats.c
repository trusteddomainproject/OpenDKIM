/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2011, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.c,v 1.27.2.1 2010/10/27 21:43:09 cm-msk Exp $
*/

#ifndef lint
static char stats_c_id[] = "@(#)$Id: stats.c,v 1.27.2.1 2010/10/27 21:43:09 cm-msk Exp $";
#endif /* !lint */

#include "build-config.h"

#ifdef _FFR_STATS

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <assert.h>
#include <syslog.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

#ifdef USE_GNUTLS
/* GnuTLS includes */
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
# ifndef MD5_DIGEST_LENGTH
#  define MD5_DIGEST_LENGTH 16
# endif /* ! MD5_DIGEST_LENGTH */
#else /* USE_GNUTLS */
/* libcrypto includes */
# include <openssl/md5.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include <dkim.h>
#include <dkim-strl.h>

/* opendkim includes */
#include "stats.h"
#include "util.h"
#include "opendkim.h"
#include "opendkim-db.h"

/* macros, defaults */
#define	DEFCT			"text/plain"
#define	DEFCTE			"7bit"
#define	DKIMF_STATS_MAXCOST	10

/* globals */
static pthread_mutex_t stats_lock;

/*
**  DKIMF_STATS_INIT -- initialize statistics
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
dkimf_stats_init(void)
{
	pthread_mutex_init(&stats_lock, NULL);
}

/*
**  DKIMF_STATS_RECORD -- record a DKIM result
**
**  Parameters:
**  	path -- path to the DB to update
**  	jobid -- job ID for the current message
**  	name -- reporter name to record
**  	prefix -- hashing prefix
**  	hdrlist -- list of headers on the message
**  	dkimv -- verifying handle from which data can be taken
**  	anon -- data are anonymized
**  	rhcnt -- count of Received: header fields
**  	sa -- client socket information
**
**  Return value:
**  	0 on success, !0 on failure
*/

int
dkimf_stats_record(char *path, u_char *jobid, char *name, char *prefix,
                   Header hdrlist, DKIM *dkimv, _Bool anon,
#ifdef _FFR_STATSEXT
                   struct statsext *se,
#endif /* _FFR_STATSEXT */
#ifdef _FFR_ATPS
                   int atps,
#endif /* _FFR_ATPS */
                   struct sockaddr *sa)
{
	_Bool validauthorsig = FALSE;
	int status = 0;
	int nsigs = 0;
#ifdef _FFR_DIFFHEADERS
	int nhdrs;
	int ndiffs;
#endif /* _FFR_DIFFHEADERS */
	int err;
	int c;
	u_int keybits;
	dkim_alg_t alg;
	dkim_canon_t bc;
	dkim_canon_t hc;
	ssize_t canonlen;
	ssize_t signlen;
	ssize_t msglen;
	struct Header *hdr;
	FILE *out;
	unsigned char *from;
	char *p;
	char *q;
#ifdef _FFR_DIFFHEADERS
	struct dkim_hdrdiff *diffs;
	unsigned char *ohdrs[MAXHDRCNT];
#endif /* _FFR_DIFFHEADERS */
	DKIM_SIGINFO **sigs;
	char tmp[BUFRSZ + 1];

	assert(path != NULL);
	assert(jobid != NULL);
	assert(name != NULL);

	pthread_mutex_lock(&stats_lock);

	/* open the log file */
	out = fopen(path, "a");
	if (out == NULL)
	{
		if (dolog)
		{
			syslog(LOG_ERR, "%s: fopen(): %s", path,
			       strerror(errno));
		}

		pthread_mutex_unlock(&stats_lock);

		return -1;
	}

	/* write version if file is new */
	if (ftell(out) == 0)
		fprintf(out, "V%d\n", DKIMS_VERSION);

	/* write info */
	status = dkim_getsiglist(dkimv, &sigs, &nsigs);
	if (status != DKIM_STAT_OK)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: dkim_getsiglist() failed", jobid);

		fclose(out);

		pthread_mutex_unlock(&stats_lock);

		return 0;
	}

	from = dkim_getdomain(dkimv);
	if (from == NULL)
	{
		if (dolog)
			syslog(LOG_ERR, "%s: dkim_getdomain() failed", jobid);

		fclose(out);

		pthread_mutex_unlock(&stats_lock);

		return 0;
	}

	if (anon)
	{
#ifdef USE_GNUTLS
		gnutls_hash_hd_t md5;
#else /* USE_GNUTLS */
		MD5_CTX md5;
#endif /* USE_GNUTLS */
		unsigned char *x;
		unsigned char dig[MD5_DIGEST_LENGTH];

#ifdef USE_GNUTLS
		if (gnutls_hash_init(&md5, GNUTLS_DIG_MD5) == 0)
		{
			if (prefix != NULL)
			{
				gnutls_hash(md5, (void *) prefix,
				            strlen(prefix));
			}
			gnutls_hash(md5, (void *) from, strlen(from));
			gnutls_hash_deinit(md5, dig);
		}
#else /* USE_GNUTLS */
		MD5_Init(&md5);
		if (prefix != NULL)
			MD5_Update(&md5, prefix, strlen(prefix));
		MD5_Update(&md5, from, strlen((char *) from));
		MD5_Final(dig, &md5);
#endif /* USE_GNUTLS */

		memset(tmp, '\0', sizeof tmp);

		x = (u_char *) tmp;
		for (c = 0; c < MD5_DIGEST_LENGTH; c++)
		{
			snprintf((char *) x, sizeof tmp - 2 * c,
			         "%02x", dig[c]);
			x += 2;
		}
	}

	fprintf(out, "M%s\t%s\t%s", jobid, name, anon ? tmp : (char *) from);

	memset(tmp, '\0', sizeof tmp);

	switch (sa->sa_family)
	{
	  case AF_INET:
	  {
		struct sockaddr_in sin4;

		memcpy(&sin4, sa, sizeof sin4);

		(void) inet_ntop(AF_INET, &sin4.sin_addr, tmp, sizeof tmp);

		break;
	  }
#ifdef AF_INET6

	  case AF_INET6:
	  {
		struct sockaddr_in6 sin6;

		memcpy(&sin6, sa, sizeof sin6);

		(void) inet_ntop(AF_INET6, &sin6.sin6_addr, tmp, sizeof tmp);

		break;
	  }
#endif /* AF_INET6 */
	}

	if (tmp[0] == '\0')
	{
		fprintf(out, "\tunknown");
	}
	else if (!anon)
	{
		fprintf(out, "\t%s", tmp);
	}
	else
	{
#ifdef USE_GNUTLS
		gnutls_hash_hd_t md5;
#else /* USE_GNUTLS */
		MD5_CTX md5;
#endif /* USE_GNUTLS */
		unsigned char *x;
		unsigned char dig[MD5_DIGEST_LENGTH];

#ifdef USE_GNUTLS
		if (gnutls_hash_init(&md5, GNUTLS_DIG_MD5) == 0)
		{
			if (prefix != NULL)
			{
				gnutls_hash(md5, (void *) prefix,
				            strlen(prefix));
			}
			gnutls_hash(md5, (void *) tmp, strlen(tmp));
			gnutls_hash_deinit(md5, dig);
		}
#else /* USE_GNUTLS */
		MD5_Init(&md5);
		if (prefix != NULL)
			MD5_Update(&md5, prefix, strlen(prefix));
		MD5_Update(&md5, tmp, strlen(tmp));
		MD5_Final(dig, &md5);
#endif /* USE_GNUTLS */

		memset(tmp, '\0', sizeof tmp);

		x = (u_char *) tmp;
		for (c = 0; c < MD5_DIGEST_LENGTH; c++)
		{
			snprintf((char *) x, sizeof tmp - 2 * c,
			         "%02x", dig[c]);
			x += 2;
		}

		fprintf(out, "\t%s", tmp);
	}

	fprintf(out, "\t%u", anon);

	fprintf(out, "\t%lu", time(NULL));

	msglen = 0;
	canonlen = 0;
	signlen = 0;
	if (nsigs > 0)
	{
		(void) dkim_sig_getcanonlen(dkimv, sigs[0], &msglen,
		                            &canonlen, &signlen);
	}

	fprintf(out, "\t%lu", canonlen);

	fprintf(out, "\t%d", nsigs);

#ifdef _FFR_ATPS
	fprintf(out, "\t%d", atps);
#endif /* _FFR_ATPS */

	fprintf(out, "\n");

	for (c = 0; c < nsigs; c++)
	{
		if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_IGNORE) != 0)
			continue;

		fprintf(out, "S");

		p = (char *) dkim_sig_getdomain(sigs[c]);

		if (anon)
		{
			int n;
#ifdef USE_GNUTLS
			gnutls_hash_hd_t md5;
#else /* USE_GNUTLS */
			MD5_CTX md5;
#endif /* USE_GNUTLS */
			unsigned char *x;
			unsigned char dig[MD5_DIGEST_LENGTH];

#ifdef USE_GNUTLS
			if (gnutls_hash_init(&md5, GNUTLS_DIG_MD5) == 0)
			{
				if (prefix != NULL)
				{
					gnutls_hash(md5, (void *) prefix,
					            strlen(prefix));
				}
				gnutls_hash(md5, (void *) p, strlen(p));
				gnutls_hash_deinit(md5, dig);
			}
#else /* USE_GNUTLS */
			MD5_Init(&md5);
			if (prefix != NULL)
				MD5_Update(&md5, prefix, strlen(prefix));
			MD5_Update(&md5, p, strlen(p));
			MD5_Final(dig, &md5);
#endif /* USE_GNUTLS */

			memset(tmp, '\0', sizeof tmp);

			x = (u_char *) tmp;
			for (n = 0; n < MD5_DIGEST_LENGTH; n++)
			{
				snprintf((char *) x, sizeof tmp - 2 * n,
				         "%02x", dig[n]);
				x += 2;
			}

			fprintf(out, "%s", tmp);
		}
		else
		{
			fprintf(out, "%s", p);
		}

		(void) dkim_sig_getsignalg(sigs[c], &alg);
		fprintf(out, "\t%d", alg);

		(void) dkim_sig_getcanons(sigs[c], &hc, &bc);
		fprintf(out, "\t%d\t%d", hc, bc);

		fprintf(out, "\t%d",
		        (dkim_sig_getflags(sigs[c]) &
		         DKIM_SIGFLAG_PASSED) != 0);

		fprintf(out, "\t%d",
		        dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH);

		(void) dkim_sig_getcanonlen(dkimv, sigs[c], &msglen,
		                            &canonlen, &signlen);
		fprintf(out, "\t%ld", (long) signlen);

		err = dkim_sig_geterror(sigs[c]);

		/* syntax error codes */
		fprintf(out, "\t%d", err);

		fprintf(out, "\t%d", dkim_sig_getdnssec(sigs[c]));

		keybits = 0;
		(void) dkim_sig_getkeysize(sigs[c], &keybits);
		fprintf(out, "\t%u", keybits);
		
		fprintf(out, "\n");
	}

#ifdef _FFR_STATSEXT
	if (se != NULL)
	{
		struct statsext *cur;

		for (cur = se; cur != NULL; cur = cur->se_next)
			fprintf(out, "X%s\t%s\n", cur->se_name, cur->se_value);
	}
#endif /* _FFR_STATSEXT */

	/* close output */
	fclose(out);

	pthread_mutex_unlock(&stats_lock);

	return 0;
}
#endif /* _FFR_STATS */
