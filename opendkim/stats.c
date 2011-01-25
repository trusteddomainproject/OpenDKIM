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

/* libcrypto includes */
#include <openssl/md5.h>

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
dkimf_stats_record(char *path, u_char *jobid, char *name, char *prefix,
                   Header hdrlist, DKIM *dkimv, dkim_policy_t pcode,
                   _Bool fromlist, _Bool anon, u_int rhcnt,
#ifdef _FFR_STATSEXT
                   struct statsext *se,
#endif /* _FFR_STATSEXT */
#ifdef _FFR_ATPS
                   int atps,
#endif /* _FFR_ATPS */
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
	u_int keybits;
	dkim_alg_t alg;
	dkim_canon_t bc;
	dkim_canon_t hc;
	off_t canonlen;
	off_t signlen;
	off_t msglen;
	DKIMF_DB db;
	struct Header *hdr;
	FILE *out;
	unsigned char *from;
	char *p;
#ifdef _FFR_DIFFHEADERS
	struct dkim_hdrdiff *diffs;
	unsigned char *ohdrs[MAXHDRCNT];
#endif /* _FFR_DIFFHEADERS */
	DKIM_SIGINFO **sigs;
	struct dkimf_db_data dbd;
	char tmp[BUFRSZ + 1];
	unsigned char ct[BUFRSZ + 1];
	unsigned char cte[BUFRSZ + 1];

	assert(path != NULL);
	assert(jobid != NULL);
	assert(name != NULL);

	strlcpy((char *) ct, DEFCT, sizeof ct);
	strlcpy((char *) cte, DEFCTE, sizeof cte);

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
		if (prefix != NULL)
			MD5_Update(&md5, prefix, strlen(prefix));
		MD5_Update(&md5, from, strlen((char *) from));
		MD5_Final(dig, &md5);

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
		MD5_CTX md5;
		unsigned char *x;
		unsigned char dig[MD5_DIGEST_LENGTH];

		MD5_Init(&md5);
		if (prefix != NULL)
			MD5_Update(&md5, prefix, strlen(prefix));
		MD5_Update(&md5, tmp, strlen(tmp));
		MD5_Final(dig, &md5);

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

	fprintf(out, "\t%lu", msglen);

	fprintf(out, "\t%d", nsigs);

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
		if (strcasecmp((char *) dkim_sig_getdomain(sigs[c]),
		               (char *) from) == 0 &&
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
			if (!dkimf_isblank(hdr->hdr_val))
			{
				for (p = hdr->hdr_val; *p != '\0'; p++)
				{
					if (!isascii(*p) || !isspace(*p))
						break;
				}

				strlcpy((char *) ct, p, sizeof ct);
				p = strchr((char *) ct, ';');
				if (p != NULL)
					*p = '\0';
				dkimf_trimspaces(ct);
				dkimf_lowercase(ct);
			}
		}
		else if (strcasecmp(hdr->hdr_hdr,
		                    "Content-Transfer-Encoding") == 0)
		{
			if (!dkimf_isblank(hdr->hdr_val))
			{
				for (p = hdr->hdr_val; *p != '\0'; p++)
				{
					if (!isascii(*p) || !isspace(*p))
						break;
				}

				strlcpy((char *) cte, hdr->hdr_val,
				        sizeof cte);
				p = strchr((char *) cte, ';');
				if (p != NULL)
					*p = '\0';
				dkimf_trimspaces(cte);
				dkimf_lowercase(cte);
			}
		}
	}

	fprintf(out, "\t%s", ct);
	fprintf(out, "\t%s", cte);

#ifdef _FFR_ATPS
	fprintf(out, "\t%d", atps);
#endif /* _FFR_ATPS */

	fprintf(out, "\n");

	for (c = 0; c < nsigs; c++)
	{
		fprintf(out, "S");

		p = (char *) dkim_sig_getdomain(sigs[c]);

		if (anon)
		{
			int n;
			MD5_CTX md5;
			unsigned char *x;
			unsigned char dig[MD5_DIGEST_LENGTH];

			MD5_Init(&md5);
			if (prefix != NULL)
				MD5_Update(&md5, prefix, strlen(prefix));
			MD5_Update(&md5, p, strlen(p));
			MD5_Final(dig, &md5);

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
		         DKIM_SIGFLAG_IGNORE) != 0);

		fprintf(out, "\t%d",
		        (dkim_sig_getflags(sigs[c]) &
		         DKIM_SIGFLAG_PASSED) != 0);

		fprintf(out, "\t%d",
		        dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH);

		(void) dkim_sig_getcanonlen(dkimv, sigs[c], &msglen,
		                            &canonlen, &signlen);
		fprintf(out, "\t%ld", (long) signlen);

		p = (char *) dkim_sig_gettagvalue(sigs[c], TRUE,
		                                  (u_char *) "t");
		fprintf(out, "\t%d", p != NULL);
		
		p = (char *) dkim_sig_gettagvalue(sigs[c], TRUE,
		                                  (u_char *) "g");
		fprintf(out, "\t%d", p != NULL);
		fprintf(out, "\t%d", p != NULL && *p != '\0' && *p != '*');

		err = dkim_sig_geterror(sigs[c]);

		/* DK-compatible keys */
		if (dkim_sig_gettagvalue(sigs[c], TRUE,
		                         (u_char *) "v") == NULL &&
		    ((p = (char *) dkim_sig_gettagvalue(sigs[c],
		                                        TRUE,
		                                        (u_char *) "g")) != NULL &&
		     *p == '\0'))
			fprintf(out, "\t1");
		else
			fprintf(out, "\t0");
		
		/* syntax error codes */
		fprintf(out, "\t%d", err);

		p = (char *) dkim_sig_gettagvalue(sigs[c], FALSE,
		                                  (u_char *) "t");
		fprintf(out, "\t%d", p != NULL);

		p = (char *) dkim_sig_gettagvalue(sigs[c], FALSE,
		                                  (u_char *) "x");
		fprintf(out, "\t%d", p != NULL);

		p = (char *) dkim_sig_gettagvalue(sigs[c], FALSE,
		                                  (u_char *) "z");
		fprintf(out, "\t%d", p != NULL);

		fprintf(out, "\t%d", dkim_sig_getdnssec(sigs[c]));

		p = (char *) dkim_sig_gettagvalue(sigs[c], FALSE,
		                                  (u_char *) "h");
		if (p == NULL)
		{
			fprintf(out, "\t-");
		}
		else
		{
			strlcpy(tmp, p, sizeof tmp);
			for (p = tmp; *p != '\0'; p++)
			{
				if (isascii(*p) && isupper(*p))
					*p = tolower(*p);
			}
			fprintf(out, "\t%s", tmp);
		}

#ifdef _FFR_DIFFHEADERS
		nhdrs = MAXHDRCNT;

		memset(tmp, '\0', sizeof tmp);

		status = dkim_ohdrs(dkimv, sigs[c], (u_char **) ohdrs, &nhdrs);
		if (status == DKIM_STAT_OK)
		{
			if (dkim_diffheaders(dkimv, hc, DKIMF_STATS_MAXCOST,
			                     (char **) ohdrs, nhdrs,
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
						strlcat(tmp, ":", sizeof tmp);

					strlcat(tmp, diffs[n].hd_old,
					        sizeof tmp);
				}

				if (n == 0)
					tmp[0] = '-';

				fprintf(out, "\t%s", tmp);

				if (ndiffs > 0)
					free(diffs);
			}
			else
			{
				fprintf(out, "\t-");
			}
		}
		else
		{
			if (dolog)
			{
				syslog(LOG_ERR, "%s: dkim_ohdrs(): %s",
				       jobid, dkim_geterror(dkimv));
			}

			fprintf(out, "\t-");
		}
#else /* _FFR_DIFFHEADERS */
		fprintf(out, "\t-");
#endif /* _FFR_DIFFHEADERS */

		/*
		**  Reporting of i= has two columns:
		**
		**  -1 -- processing error or data not available
		**  0 -- "i=" not present
		**  1 -- "i=" present with default value
		**  2 -- "i=" present but has some other value (a subdomain)
		**
		**  -1 -- processing error or data not available
		**  0 -- "i=" not present
		**  1 -- "i=" present but with no local-part
		**  2 -- "i=" has a local-part matching that of the From: line
		**  3 -- "i=" has some other local-part
		*/

		p = (char *) dkim_sig_gettagvalue(sigs[c], FALSE,
		                                  (u_char *) "i");
		if (p == NULL)
		{
			fprintf(out, "\t0\t0");
		}
		else
		{
			int user = -1;
			int domain = -1;
			char *at;

			at = strchr(p, '@');
			if (at != NULL)
			{
				if (strcasecmp((char *) from, at + 1) == 0)
					domain = 1;
				else
					domain = 2;

				if (p == at)
				{
					user = 1;
				}
				else
				{
					size_t ulen;
					size_t llen;
					unsigned char *local;

					local = dkim_getuser(dkimv);
					llen = strlen((char *) local);

					ulen = at - p;

					if (llen == ulen &&
					    strncmp((char *) local,
					            p, ulen) == 0)
						user = 2;
					else
						user = 3;
				}
			}

			fprintf(out, "\t%d\t%d", domain, user);
		}

		p = (char *) dkim_sig_gettagvalue(sigs[c], TRUE,
		                                  (u_char *) "s");
		if (p == NULL)
			fprintf(out, "\t0");
		else if (*p == '*')
			fprintf(out, "\t1");
		else if (strcasecmp(p, "email") == 0)
			fprintf(out, "\t2");
		else
			fprintf(out, "\t3");

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
