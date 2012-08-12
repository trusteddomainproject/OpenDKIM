/*
**  Copyright (c) 2010-2012, The Trusted Domain Project.  All rights reserved.
**
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>

/* openssl includes */
#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
# include <gnutls/abstract.h>
# include <gnutls/x509.h>
#else /* USE_GNUTLS */
# include <openssl/rsa.h>
# include <openssl/pem.h>
# include <openssl/evp.h>
# include <openssl/bio.h>
#endif /* USE_GNUTLS */

#ifndef FALSE
# define FALSE		0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* ! TRUE */
#ifndef SHA_DIGEST_LENGTH
# define SHA_DIGEST_LENGTH 20
#endif /* ! SHA_DIGEST_LENGTH */
#ifndef SHA256_DIGEST_LENGTH
# define SHA256_DIGEST_LENGTH 32
#endif /* ! SHA256_DIGEST_LENGTH */

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "opendkim-db.h"
#include "util.h"
#include "config.h"
#include "opendkim-config.h"

/* definitions */
#define	ATPSZONE	"._atps"
#define	BASE32_LENGTH	32
#define	BUFRSZ		256
#define	CMDLINEOPTS	"AC:E:h:o:N:r:R:St:T:u:v"
#define	DEFEXPIRE	604800
#define	DEFREFRESH	10800
#define	DEFRETRY	1800
#define	DEFTTL		86400
#define	HOSTMASTER	"hostmaster"
#define	MAXNS		16
#define	VALIDATPS	"v=ATPS1"

/* globals */
char *progname;

/*
**  USAGE -- print usage message and exit
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s [opts] [dataset]\n"
	                "\t-A          \tinclude '._atps' suffix\n"
	                "\t-C user@host\tcontact address to include in SOA\n"
	                "\t-E secs     \tuse specified expiration time in SOA\n"
	                "\t-h hash     \thash algorithm\n"
	                "\t-o file     \toutput file\n"
	                "\t-N ns[,...] \tlist NS records\n"
	                "\t-r secs     \tuse specified refresh time in SOA\n"
	                "\t-R secs     \tuse specified retry time in SOA\n"
	                "\t-S          \twrite an SOA record\n"
	                "\t-t secs     \tuse specified per-record TTL\n"
	                "\t-T secs     \tuse specified default TTL in SOA\n"
	                "\t-u domain   \tproduce nsupdate(8) script\n"
	                "\t-v          \tverbose output\n",
		progname, progname);

	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	_Bool suffix = FALSE;
	_Bool writesoa = FALSE;
	_Bool nsupdate = FALSE;
	int c;
	int status;
	int verbose = 0;
	int ttl = -1;
	int defttl = DEFTTL;
	int expire = DEFEXPIRE;
	int refresh = DEFREFRESH;
	int retry = DEFRETRY;
	int nscount = 0;
	time_t now;
	size_t dlen;
	size_t b32len;
	size_t shalen;
	char *p;
	char *dataset = NULL;
	char *udomain = NULL;
	char *outfile = NULL;
	char *hash = NULL;
	char *contact = NULL;
	char *nameservers = NULL;
	char *nslist[MAXNS];
	FILE *out;
	DKIMF_DB db;
#ifdef USE_GNUTLS
	gnutls_hash_hd_t sha;
#else /* USE_GNUTLS */
	SHA_CTX sha;
# ifdef HAVE_SHA256
	SHA256_CTX sha256;
# endif /* HAVE_SHA256 */
#endif /* USE_GNUTLS */
	char domain[DKIM_MAXHOSTNAMELEN + 1];
	char hostname[DKIM_MAXHOSTNAMELEN + 1];
#ifdef HAVE_SHA256
	char shaout[SHA256_DIGEST_LENGTH];
#else /* HAVE_SHA256 */
	char shaout[SHA_DIGEST_LENGTH];
#endif /* HAVE_SHA256 */
	char base32[BASE32_LENGTH + 1];
	char value[BUFRSZ + 1];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'A':
			suffix = TRUE;
			break;

		  case 'C':
			contact = strdup(optarg);
			break;

		  case 'E':
			expire = strtol(optarg, &p, 10);
			if (*p != '\0' || expire < 0)
			{
				fprintf(stderr, "%s: invalid expire value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'h':
			if (strcasecmp(optarg, "sha1") != 0 &&
			    strcasecmp(optarg, "sha256") != 0 &&
			    strcasecmp(optarg, "none") != 0)
			{
				fprintf(stderr, "%s: invalid hash algorithm\n",
				        progname);
				return EX_USAGE;
			}
#ifndef HAVE_SHA256
			else if (strcasecmp(optarg, "sha256") == 0)
			{
				fprintf(stderr,
				        "%s: hash algorithm \"%s\" not supported\n",
				        progname, optarg);
				return EX_SOFTWARE;
			}
#endif /* ! HAVE_SHA256 */
			hash = optarg;
			if (strcasecmp(hash, "sha1") == 0)
				shalen = SHA_DIGEST_LENGTH;
			else
				shalen = SHA256_DIGEST_LENGTH;
			break;

		  case 'N':
			nameservers = strdup(optarg);
			break;

		  case 'o':
			outfile = optarg;
			break;

		  case 'r':
			refresh = strtol(optarg, &p, 10);
			if (*p != '\0' || refresh < 0)
			{
				fprintf(stderr, "%s: invalid refresh value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'R':
			retry = strtol(optarg, &p, 10);
			if (*p != '\0' || retry < 0)
			{
				fprintf(stderr, "%s: invalid retry value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'S':
			writesoa = TRUE;
			break;

		  case 't':
			ttl = strtol(optarg, &p, 10);
			if (*p != '\0' || ttl < 0)
			{
				fprintf(stderr, "%s: invalid TTL value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'T':
			defttl = strtol(optarg, &p, 10);
			if (*p != '\0' || defttl < 0)
			{
				fprintf(stderr,
				        "%s: invalid default TTL value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'u':
			nsupdate = TRUE;
			udomain = optarg;
			break;

		  case 'v':
			verbose++;
			break;

		  default:
			return usage();
		}
	}

	if (optind != argc)
		dataset = argv[optind];

	status = dkimf_db_open(&db, dataset, DKIMF_DB_FLAG_READONLY,
	                       NULL, NULL);
	if (status != 0)
	{
		fprintf(stderr, "%s: dkimf_db_open() failed\n", progname);
		return 1;
	}

	if (dkimf_db_type(db) == DKIMF_DB_TYPE_REFILE)
	{
		fprintf(stderr, "%s: invalid data set type\n", progname);
		(void) dkimf_db_close(db);
		return 1;
	}

	if (verbose > 0)
		fprintf(stderr, "%s: database opened\n", progname);

	if (outfile != NULL)
	{
		out = fopen(outfile, "w");
		if (out == NULL)
		{
			fprintf(stderr, "%s: %s: fopen(): %s\n",
			        progname, outfile, strerror(errno));
			(void) dkimf_db_close(db);
			return 1;
		}
	}
	else
	{
		out = stdout;
	}

	if (nameservers != NULL)
	{
		for (p = strtok(nameservers, ",");
		     p != NULL && nscount < MAXNS;
		     p = strtok(NULL, ","))
			nslist[nscount++] = p;
	}

	memset(hostname, '\0', sizeof hostname);
	gethostname(hostname, sizeof hostname);

	if (nscount == 0)
		nslist[nscount++] = hostname;

	(void) time(&now);

	if (!nsupdate)
	{
		fprintf(out, "; DKIM ATPS zone data\n");
		fprintf(out, "; auto-generated by %s at %s\n", progname,
		        ctime(&now));
	}

	if (writesoa && !nsupdate)
	{
		struct tm *tm;

		fprintf(out, "@\tIN\tSOA\t%s\t", nslist[0]);

		if (contact != NULL)
		{
			for (p = contact; *p != '\0'; p++)
			{
				if (*p == '@')
					*p = '.';
			}

			fprintf(out, "%s", contact);
		}
		else
		{
			struct passwd *pwd;

			pwd = getpwuid(getuid());

			fprintf(out, "%s.%s",
			        pwd == NULL ? HOSTMASTER : pwd->pw_name,
			        hostname);
		}

		tm = localtime(&now);

		fprintf(out,
		        "\t (\n"
		        "\t%04d%02d%02d%02d   ; Serial (yyyymmddhh)\n"
		        "\t%-10d   ; Refresh\n"
		        "\t%-10d   ; Retry\n"
		        "\t%-10d   ; Expire\n"
		        "\t%-10d ) ; Default\n\n",
		        tm->tm_year + 1900,
		        tm->tm_mon + 1,
		        tm->tm_mday,
		        tm->tm_hour,
		        refresh, retry, expire, defttl);
	}

	if (nameservers != NULL && !nsupdate)
	{
		for (c = 0; c < nscount; c++)
			fprintf(out, "\tIN\tNS\t%s\n", nslist[c]);

		fprintf(out, "\n");
	}

	if (nsupdate)
	{
		fprintf(out, "server %s\n", nslist[0]);
		fprintf(out, "zone %s\n", udomain);
	}

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	for (c = 0; ; c++)
	{
		memset(domain, '\0', sizeof domain);
		dlen = sizeof domain;

		status = dkimf_db_walk(db, c == 0, domain, &dlen, NULL, 0);
		if (status == -1)
		{
			fprintf(stderr, "%s: dkimf_db_walk(%d) failed\n",
			        progname, c);
			(void) dkimf_db_close(db);
			return 1;
		}
		else if (status == 1)
		{
			break;
		}

		/* convert to lowercase */
		dkimf_lowercase(domain);

		memset(base32, '\0', sizeof base32);

		if (hash == NULL || strcasecmp(hash, "none") != 0)
		{
			/* compute SHA1 hash */
#ifdef USE_GNUTLS
# ifdef HAVE_SHA256
			if (hash == NULL || strcasecmp(hash, "sha256") == 0)
			{
				(void) gnutls_hash_init(&sha,
				                        GNUTLS_DIG_SHA256);
			}
			else
			{
				(void) gnutls_hash_init(&sha, GNUTLS_DIG_SHA1);
			}
# else /* HAVE_SHA256 */
			(void) gnutls_hash_init(&sha, GNUTLS_DIG_SHA1);
# endif /* HAVE_SHA256 */
			(void) gnutls_hash(sha, domain, strlen(domain));
			(void) gnutls_hash_deinit(sha, shaout);
#else /* USE_GNUTLS */
# ifdef HAVE_SHA256
			if (hash == NULL || strcasecmp(hash, "sha256") == 0)
			{
				SHA256_Init(&sha256);
				SHA256_Update(&sha256, domain, strlen(domain));
				SHA256_Final(shaout, &sha256);
			}
			else
			{
				SHA1_Init(&sha);
				SHA1_Update(&sha, domain, strlen(domain));
				SHA1_Final(shaout, &sha);
			}
# else /* HAVE_SHA256 */
			SHA1_Init(&sha);
			SHA1_Update(&sha, domain, strlen(domain));
			SHA1_Final(shaout, &sha);
# endif /* HAVE_SHA256 */
#endif /* USE_GNUTLS */

			/* encode with base32 */
			memset(base32, '\0', sizeof base32);
			b32len = sizeof base32 - 1;
			(void) dkim_base32_encode(base32, &b32len, shaout,
			                          shalen);
		}

		/* generate output */
		snprintf(value, sizeof value, "%s; d=%s", VALIDATPS, domain);

		if (nsupdate)
		{
			fprintf(out, "update add %s%s TXT %d \"%s\"\n",
			        base32[0] == '\0' ? domain : base32,
			        suffix ? ATPSZONE : "",
				ttl == -1 ? defttl : ttl,
			        value);
		}
		else if (ttl == -1)
		{
			fprintf(out, "%s%s\tIN\tTXT\t\"%s\"\n",
			        base32[0] == '\0' ? domain : base32,
			        suffix ? ATPSZONE : "",
			        value);
		}
		else
		{
			fprintf(out, "%s%s\t%d\tIN\tTXT\t\"%s\"\n",
			        base32[0] == '\0' ? domain : base32,
			        suffix ? ATPSZONE : "", ttl,
			        value);
		}
	}

	(void) dkimf_db_close(db);

	if (nsupdate)
		fprintf(out, "send\nanswer\n");

	if (out != stdout)
		fclose(out);

	if (verbose > 0)
	{
		fprintf(stdout, "%s: %d record%s written\n",
		        progname, c, c == 1 ? "" : "s");
	}

	return 0;
}
