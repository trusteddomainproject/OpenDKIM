/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.c,v 1.14.10.6 2010/08/19 19:56:22 cm-msk Exp $
*/

#ifndef lint
static char stats_c_id[] = "@(#)$Id: stats.c,v 1.14.10.6 2010/08/19 19:56:22 cm-msk Exp $";
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
#include <stdio.h>

/* libcrypto includes */
#include <openssl/md5.h>

/* libopendkim includes */
#include <dkim.h>
#include <dkim-strl.h>

/* opendkim ncludes */
#include "stats.h"
#include "util.h"
#include "opendkim.h"
#include "opendkim-db.h"

/* macros, defaults */
#define	DEFCT		"text/plain"
#define	DEFCTE		"7bit"

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
**  	hdrlist -- list of headers on the message
**  	dkimv -- verifying handle from which data can be taken
**  	pcode -- policy code
**  	fromlist -- message appeared to be from a list
**  	anon -- data are anonymized
**  	rhcnt -- count of Received: header fields
**  	sa -- client socket information
**
**  Return value:
**  	0 on success, !0 on failure
*/

int
dkimf_stats_record(char *path, char *jobid, char *name,
                   Header hdrlist, DKIM *dkimv, dkim_policy_t pcode,
                   _Bool fromlist, _Bool anon, u_int rhcnt,
                   struct sockaddr *sa)
{
	_Bool exists;
	_Bool sigfailed;
	_Bool sigfailedbody;
	_Bool sigpassed;
	_Bool validauthorsig = FALSE;
	int status = 0;
	int version;
	int nsigs = 0;
#ifdef _FFR_DIFFHEADERS
	int nhdrs;
	int ndiffs;
#endif /* _FFR_DIFFHEADERS */
	int err;
	int c;
	dkim_alg_t alg;
	dkim_canon_t bc;
	dkim_canon_t hc;
	off_t canonlen;
	off_t signlen;
	off_t msglen;
	DKIMF_DB db;
	struct Header *hdr;
	FILE *out;
	char *from;
	char *p;
#ifdef _FFR_DIFFHEADERS
	struct dkim_hdrdiff *diffs;
	char *ohdrs[MAXHDRCNT];
#endif /* _FFR_DIFFHEADERS */
	DKIM_SIGINFO **sigs;
	struct dkimf_db_data dbd;
	char tmp[BUFRSZ + 1];
	char ct[BUFRSZ + 1];
	char cte[BUFRSZ + 1];

	assert(path != NULL);
	assert(jobid != NULL);
	assert(name != NULL);

	strlcpy(ct, DEFCT, sizeof ct);
	strlcpy(cte, DEFCTE, sizeof cte);

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
		MD5_CTX md5;
		unsigned char *x;
		unsigned char dig[MD5_DIGEST_LENGTH];

		MD5_Init(&md5);
		MD5_Update(&md5, from, strlen(from));
		MD5_Final(dig, &md5);

		memset(tmp, '\0', sizeof tmp);

		x = tmp;
		for (c = 0; c < MD5_DIGEST_LENGTH; c++)
		{
			snprintf(x, sizeof tmp - 2 * c, "%02x", dig[c]);
			x += 2;
		}
	}

	fprintf(out, "M%s\t%s\t%s", jobid, name, anon ? tmp : from);

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
		MD5_CTX md5;
		unsigned char *x;
		unsigned char dig[MD5_DIGEST_LENGTH];

		MD5_Init(&md5);
		MD5_Update(&md5, tmp, strlen(tmp));
		MD5_Final(dig, &md5);

		memset(tmp, '\0', sizeof tmp);

		x = tmp;
		for (c = 0; c < MD5_DIGEST_LENGTH; c++)
		{
			snprintf(x, sizeof tmp - 2 * c, "%02x", dig[c]);
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

	fprintf(out, "\t%lu", msglen);

	fprintf(out, "\t%d", dkim_getpresult(dkimv) == DKIM_PRESULT_FOUND);

	switch (pcode)
	{
	  case DKIM_POLICY_UNKNOWN:
		fprintf(out, "\t1\t0\t0");
		break;

	  case DKIM_POLICY_ALL:
		fprintf(out, "\t0\t1\t0");
		break;

	  case DKIM_POLICY_DISCARDABLE:
		fprintf(out, "\t0\t0\t1");
		break;

	  default:
		fprintf(out, "\t0\t0\t0");
		break;
	}

	for (c = 0; c < nsigs; c++)
	{
		if (strcasecmp(dkim_sig_getdomain(sigs[c]), from) == 0 &&
		    dkim_sig_geterror(sigs[c]) == DKIM_SIGERROR_OK)
		{
			validauthorsig = TRUE;
			break;
		}
	}

	fprintf(out, "\t%d", (pcode == DKIM_POLICY_ALL ||
	                      pcode == DKIM_POLICY_DISCARDABLE) &&
	                     !validauthorsig);

	fprintf(out, "\t%d", fromlist);

	fprintf(out, "\t%u", rhcnt);

	for (hdr = hdrlist; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (strcasecmp(hdr->hdr_hdr, "Content-Type") == 0)
		{
			strlcpy(ct, hdr->hdr_val, sizeof ct);
			p = strchr(ct, ';');
			if (p != NULL)
				*p = '\0';
		}
		else if (strcasecmp(hdr->hdr_hdr,
		                    "Content-Transfer-Encoding") == 0)
		{
			strlcpy(cte, hdr->hdr_val, sizeof cte);
		}
	}

	fprintf(out, "\t%s", ct);
	fprintf(out, "\t%s", cte);

	fprintf(out, "\n");

	for (c = 0; c < nsigs; c++)
	{
		fprintf(out, "S");

		fprintf(out, "%s", dkim_sig_getdomain(sigs[c]));

		(void) dkim_sig_getsignalg(sigs[c], &alg);
		fprintf(out, "\t%d", alg);

		(void) dkim_sig_getcanons(sigs[c], &hc, &bc);
		fprintf(out, "\t%d\t%d", hc, bc);

		fprintf(out, "\t%d",
		        (dkim_sig_getflags(sigs[c]) &
		         DKIM_SIGFLAG_IGNORE) != 0);

		fprintf(out, "\t%d",
		        (dkim_sig_getflags(sigs[c]) &
		         DKIM_SIGFLAG_PASSED) != 0);

		fprintf(out, "\t%d",
		        dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH);

		(void) dkim_sig_getcanonlen(dkimv, sigs[c], &msglen,
		                            &canonlen, &signlen);
		fprintf(out, "\t%ld", (long) signlen);

		p = dkim_sig_gettagvalue(sigs[c], TRUE, "t");
		fprintf(out, "\t%d", p != NULL);
		
		p = dkim_sig_gettagvalue(sigs[c], TRUE, "g");
		fprintf(out, "\t%d", p != NULL);
		fprintf(out, "\t%d", p != NULL && *p != '\0' && *p != '*');

		err = dkim_sig_geterror(sigs[c]);

		fprintf(out, "\t%d", err == DKIM_SIGERROR_DNSSYNTAX ||
		                     err == DKIM_SIGERROR_KEYHASHMISMATCH ||
		                     err == DKIM_SIGERROR_KEYDECODE ||
		                     err == DKIM_SIGERROR_MULTIREPLY);

		fprintf(out, "\t%d", err == DKIM_SIGERROR_NOKEY);

		if (dkim_sig_gettagvalue(sigs[c], TRUE, "v") == NULL &&
		    ((p = dkim_sig_gettagvalue(sigs[c], TRUE, "g")) != NULL &&
		     *p == '\0'))
			fprintf(out, "\t1");
		else
			fprintf(out, "\t0");
		
		fprintf(out, "\t%d", err == DKIM_SIGERROR_KEYREVOKED);

		fprintf(out, "\t%d", err == DKIM_SIGERROR_VERSION ||
		                     err == DKIM_SIGERROR_DOMAIN ||
		                     err == DKIM_SIGERROR_TIMESTAMPS ||
		                     err == DKIM_SIGERROR_MISSING_C ||
		                     err == DKIM_SIGERROR_INVALID_HC ||
		                     err == DKIM_SIGERROR_INVALID_BC ||
		                     err == DKIM_SIGERROR_MISSING_A ||
		                     err == DKIM_SIGERROR_INVALID_A ||
		                     err == DKIM_SIGERROR_MISSING_H ||
		                     err == DKIM_SIGERROR_INVALID_L ||
		                     err == DKIM_SIGERROR_INVALID_Q ||
		                     err == DKIM_SIGERROR_INVALID_QO ||
		                     err == DKIM_SIGERROR_MISSING_D ||
		                     err == DKIM_SIGERROR_EMPTY_D ||
		                     err == DKIM_SIGERROR_MISSING_S ||
		                     err == DKIM_SIGERROR_EMPTY_S ||
		                     err == DKIM_SIGERROR_MISSING_B ||
		                     err == DKIM_SIGERROR_EMPTY_B ||
		                     err == DKIM_SIGERROR_CORRUPT_B ||
		                     err == DKIM_SIGERROR_MISSING_BH ||
		                     err == DKIM_SIGERROR_EMPTY_BH ||
		                     err == DKIM_SIGERROR_CORRUPT_BH ||
		                     err == DKIM_SIGERROR_EMPTY_H ||
		                     err == DKIM_SIGERROR_TOOLARGE_L);

		p = dkim_sig_gettagvalue(sigs[c], FALSE, "t");
		fprintf(out, "\t%d", p != NULL);

		fprintf(out, "\t%d", err == DKIM_SIGERROR_FUTURE);

		p = dkim_sig_gettagvalue(sigs[c], FALSE, "x");
		fprintf(out, "\t%d", p != NULL);

		p = dkim_sig_gettagvalue(sigs[c], FALSE, "z");
		fprintf(out, "\t%d", p != NULL);

		fprintf(out, "\t%d", dkim_sig_getdnssec(sigs[c]));

		p = dkim_sig_gettagvalue(sigs[c], FALSE, "h");
		fprintf(out, "\t%s", p == NULL ? "-" : p);

#ifdef _FFR_DIFFHEADERS
		nhdrs = MAXHDRCNT;

		memset(tmp, '\0', sizeof tmp);

		if (dkim_ohdrs(dkimv, sigs[c], ohdrs, &nhdrs) == DKIM_STAT_OK)
		{
			if (dkim_diffheaders(dkimv, 0, ohdrs, nhdrs,
			                     &diffs, &ndiffs) == DKIM_STAT_OK)
			{
				int n;
				char *p;

				for (n = 0; n < ndiffs; n++)
				{
					p = strchr(diffs[n].hd_old, ':');
					if (p != NULL)
						*p = '\0';
					dkimf_lowercase(diffs[n].hd_old);

					if (tmp[0] != '\0')
						strlcat(tmp, ",", sizeof tmp);

					strlcat(tmp, diffs[n].hd_old,
					        sizeof tmp);
				}

				fprintf(out, "\t%s", tmp);

				if (ndiffs > 0)
					free(diffs);
			}
		}
#else /* _FFR_DIFFHEADERS */
		fprintf(out, "\t-");
#endif /* _FFR_DIFFHEADERS */

		fprintf(out, "\n");
	}

	/* close output */
	fclose(out);

	pthread_mutex_unlock(&stats_lock);

	return 0;
}
#endif /* _FFR_STATS */
