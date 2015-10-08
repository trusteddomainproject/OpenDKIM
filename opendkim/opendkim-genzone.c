/*
**  Copyright (c) 2010-2015, The Trusted Domain Project.  All rights reserved.
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
#ifndef MIN
# define MIN(x,y)	((x) < (y) ? (x) : (y))
#endif /* ! MIN */

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "opendkim-db.h"
#include "config.h"
#include "opendkim-config.h"

/* definitions */
#define	BUFRSZ		1024
#define	CMDLINEOPTS	"C:d:DE:Fo:N:r:R:sSt:T:uvx:"
#define	DEFCONFFILE	CONFIG_BASE "/opendkim.conf"
#define	DEFEXPIRE	604800
#define	DEFREFRESH	10800
#define	DEFRETRY	1800
#define	DEFTTL		86400
#define	DKIMZONE	"._domainkey"
#define	HOSTMASTER	"hostmaster"
#define	LARGEBUFRSZ	8192
#define	MARGIN		75
#define	MAXNS		16

/* globals */
char *progname;

/*
**  STRFLEN -- determine length of a formatted string
**
**  Parameters:
**  	str -- string of interest
**
**  Return value:
**  	Rendered width (i.e. expand tabs, etc.).
*/

int
strflen(char *str)
{
	int olen = 0;
	char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (*p == '\t')
			olen += 8 - (olen % 8);
		else
			olen++;
	}

	return olen;
}
	
/*
**  LOADKEY -- resolve a key
**
**  Parameters:
**  	buf -- key buffer
**  	buflen -- pointer to key buffer's length (updated)
**
**  Return value:
**  	TRUE on successful load, false otherwise
*/

int
loadkey(char *buf, size_t *buflen)
{
	assert(buf != NULL);
	assert(buflen != NULL);

	if (buf[0] == '/' || (buf[0] == '.' && buf[1] == '/') ||
	    (buf[0] == '.' && buf[1] == '.' && buf[2] == '/'))
	{
		int fd;
		int status;
		ssize_t rlen;
		struct stat s;

		fd = open(buf, O_RDONLY);
		if (fd < 0)
			return FALSE;

		status = fstat(fd, &s);
		if (status != 0)
		{
			close(fd);
			return FALSE;
		}

		*buflen = MIN(s.st_size, *buflen);
		rlen = read(fd, buf, *buflen);
		close(fd);

		if (rlen < *buflen)
			return FALSE;
	}
	else
	{
		*buflen = strlen(buf);
	}

	return TRUE;
}

/*
**  DESPACE -- remove spaces from a string
**
**  Parameters:
**  	str -- string to update
**
**  Return value:
**  	None.
*/

void
despace(char *str)
{
	char *p;
	char *q;

	assert(str != NULL);

	for (p = str, q = str; ; p++)
	{
		if (isascii(*p) && isspace(*p))
			continue;
		else
			*q++ = *p;
		if (*p == '\0')
			break;
	}
}
	
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
	                "\t-C user@host\tcontact address to include in SOA\n"
	                "\t-d domain   \twrite keys for named domain only\n"
	                "\t-D          \tinclude '._domainkey' suffix\n"
	                "\t-E secs     \tuse specified expiration time in SOA\n"
	                "\t-F          \tinclude '._domainkey' suffix and domainname\n"
	                "\t-o file     \toutput file\n"
	                "\t-N ns[,...] \tlist NS records\n"
	                "\t-r secs     \tuse specified refresh time in SOA\n"
	                "\t-R secs     \tuse specified retry time in SOA\n"
	                "\t-s          \twith -d, also match subdomains\n"
	                "\t-S          \twrite an SOA record\n"
	                "\t-t secs     \tuse specified per-record TTL\n"
	                "\t-T secs     \tuse specified default TTL in SOA\n"
	                "\t-u          \tproduce output suitable for use by \"nsupdate\"\n"
	                "\t-v          \tverbose output\n"
	                "\t-x file     \tconfiguration file\n",
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
	_Bool seenlf;
	_Bool nsupdate = FALSE;
	_Bool suffix = FALSE;
	_Bool fqdnsuffix = FALSE;
	_Bool subdomains = FALSE;
	_Bool writesoa = FALSE;
	int c;
	int status;
	int verbose = 0;
	int olen;
	int ttl = -1;
	int defttl = DEFTTL;
	int expire = DEFEXPIRE;
	int refresh = DEFREFRESH;
	int retry = DEFRETRY;
	int nscount = 0;
	long len;
	time_t now;
	size_t keylen;
	size_t domain_len;
	size_t onlydomain_len;
	char *p;
	char *dataset = NULL;
	char *outfile = NULL;
	char *onlydomain = NULL;
	char *contact = NULL;
	char *nameservers = NULL;
	char *configfile = NULL;
	char *err = NULL;
	char *nslist[MAXNS];
	FILE *out;
#ifdef USE_GNUTLS
	gnutls_x509_privkey_t xprivkey;
	gnutls_privkey_t privkey;
	gnutls_pubkey_t pubkey;
	gnutls_datum_t key;
#else /* USE_GNUTLS */
	BIO *private;
	BIO *outbio = NULL;
	EVP_PKEY *pkey;
	RSA *rsa;
#endif /* USE_GNUTLS */
	DKIMF_DB db;
	char keyname[BUFRSZ + 1];
	char domain[BUFRSZ + 1];
	char selector[BUFRSZ + 1];
	char tmpbuf[BUFRSZ + 1];
	char hostname[DKIM_MAXHOSTNAMELEN + 1];
	char keydata[LARGEBUFRSZ];
	char derdata[LARGEBUFRSZ];
	struct dkimf_db_data dbd[3];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'C':
			contact = strdup(optarg);
			break;

		  case 'd':
			onlydomain = optarg;
			break;

		  case 'D':
			suffix = TRUE;
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

		  case 'F':
			suffix = TRUE;
			fqdnsuffix = TRUE;
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

		  case 's':
			subdomains = TRUE;
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
			break;

		  case 'v':
			verbose++;
			break;

		  case 'x':
			configfile = optarg;
			break;

		  default:
			return usage();
		}
	}

	/* sanity check */
	if (subdomains && onlydomain == NULL) {
		fprintf(stderr, "%s: subdomain matching requires a domain\n",
		        progname);
		return EX_USAGE;
	}

	if (optind != argc)
		dataset = argv[optind];

	/* process config file */
	if (configfile == NULL && access(DEFCONFFILE, R_OK) == 0)
		configfile = DEFCONFFILE;
	if (configfile != NULL)
	{
#ifdef USE_LDAP
		_Bool ldap_usetls = FALSE;
#endif /* USE_LDAP */
		u_int line = 0;
#ifdef USE_LDAP
		char *ldap_authmech = NULL;
# ifdef USE_SASL
		char *ldap_authname = NULL;
		char *ldap_authrealm = NULL;
		char *ldap_authuser = NULL;
# endif /* USE_SASL */
		char *ldap_bindpw = NULL;
		char *ldap_binduser = NULL;
#endif /* USE_LDAP */
		struct config *cfg;
		char path[MAXPATHLEN + 1];

		cfg = config_load(configfile, dkimf_config,
		                  &line, path, sizeof path, NULL);

		if (cfg == NULL)
		{
			fprintf(stderr,
			        "%s: %s: configuration error at line %u\n",
			        progname, path, line);
			return EX_CONFIG;
		}

		if (dataset == NULL)
		{
			(void) config_get(cfg, "KeyTable",
			                  &dataset, sizeof dataset);
		}

#ifdef USE_LDAP
		(void) config_get(cfg, "LDAPUseTLS",
		                  &ldap_usetls, sizeof ldap_usetls);

		if (ldap_usetls)
			dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_USETLS, "y");
		else
			dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_USETLS, "n");

		(void) config_get(cfg, "LDAPAuthMechanism",
		                  &ldap_authmech, sizeof ldap_authmech);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHMECH,
		                        ldap_authmech);

# ifdef USE_SASL
		(void) config_get(cfg, "LDAPAuthName",
		                  &ldap_authname, sizeof ldap_authname);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHNAME,
		                        ldap_authname);

		(void) config_get(cfg, "LDAPAuthRealm",
		                  &ldap_authrealm, sizeof ldap_authrealm);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHREALM,
		                        ldap_authrealm);

		(void) config_get(cfg, "LDAPAuthUser",
		                  &ldap_authuser, sizeof ldap_authuser);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHUSER,
		                        ldap_authuser);
# endif /* USE_SASL */

		(void) config_get(cfg, "LDAPBindPassword",
		                  &ldap_bindpw, sizeof ldap_bindpw);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_BINDPW, ldap_bindpw);

		(void) config_get(cfg, "LDAPBindUser",
		                  &ldap_binduser, sizeof ldap_binduser);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_BINDUSER,
		                        ldap_binduser);
#endif /* USE_LDAP */
	}

	if (dataset == NULL)
		return usage();

#ifndef USE_GNUTLS
	outbio = BIO_new(BIO_s_mem());
	if (outbio == NULL)
	{
		fprintf(stderr, "%s: BIO_new() failed\n", progname);
		return 1;
	}
#endif /* ! USE_GNUTLS */

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	status = dkimf_db_open(&db, dataset, DKIMF_DB_FLAG_READONLY,
	                       NULL, &err);
	if (status != 0)
	{
		fprintf(stderr, "%s: dkimf_db_open(): %s\n", progname, err);
#ifndef USE_GNUTLS
		(void) BIO_free(outbio);
#endif /* ! USE_GNUTLS */
		return 1;
	}

	if (dkimf_db_type(db) == DKIMF_DB_TYPE_REFILE)
	{
		fprintf(stderr, "%s: invalid data set type\n", progname);
#ifndef USE_GNUTLS
		(void) BIO_free(outbio);
#endif /* ! USE_GNUTLS */
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
#ifndef USE_GNUTLS
			(void) BIO_free(outbio);
#endif /* ! USE_GNUTLS */
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
		fprintf(out, "; DKIM public key zone data\n");
		if (onlydomain != NULL)
			fprintf(out, "; for %s\n", onlydomain);
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
		fprintf(out, "server %s\n", nslist[0]);

	dbd[0].dbdata_buffer = domain;
	dbd[1].dbdata_buffer = selector;
	dbd[2].dbdata_buffer = keydata;

	for (c = 0; ; c++)
	{
		memset(keyname, '\0', sizeof keyname);
		memset(domain, '\0', sizeof domain);
		memset(selector, '\0', sizeof selector);
		memset(keydata, '\0', sizeof keydata);

		dbd[0].dbdata_buflen = sizeof domain;
		dbd[1].dbdata_buflen = sizeof selector;
		dbd[2].dbdata_buflen = sizeof keydata;

		keylen = sizeof keyname;

		status = dkimf_db_walk(db, c == 0, keyname, &keylen, dbd, 3);
		if (status == -1)
		{
			char err[BUFRSZ];

			dkimf_db_strerror(db, err, sizeof err);
			fprintf(stderr, "%s: dkimf_db_walk(%d) failed: %s\n",
			        progname, c, err);
			(void) dkimf_db_close(db);
#ifndef USE_GNUTLS
			(void) BIO_free(outbio);
#endif /* ! USE_GNUTLS */
			return 1;
		}
		else if (status == 1)
		{
			break;
		}

		if (subdomains) {
			domain_len = strlen(domain);
			onlydomain_len = strlen(onlydomain);

			if ((domain_len == onlydomain_len &&
			     strcasecmp(domain, onlydomain) == 0) ||
			    (domain_len > onlydomain_len &&
			     domain[domain_len - onlydomain_len - 1] == '.' &&
			     strcasecmp(domain + domain_len - onlydomain_len,
			                onlydomain) == 0)) {
				fprintf(stderr, "%s: record %d for '%s' skipped\n",
					progname, c, keyname);
				continue;
			}
		} else {
			if (onlydomain != NULL &&
			    strcasecmp(domain, onlydomain) != 0)
			{
				fprintf(stderr, "%s: record %d for '%s' skipped\n",
				        progname, c, keyname);

				continue;
			}
		}

		if (verbose > 1)
		{
			fprintf(stderr, "%s: record %d for '%s' retrieved\n",
			        progname, c, keyname);
		}

		keylen = sizeof keydata;
		if (!loadkey(keydata, &keylen))
		{
			fprintf(stderr, "%s: key for '%s' load failed\n",
			        progname, keyname);
			(void) dkimf_db_close(db);
#ifndef USE_GNUTLS
			(void) BIO_free(outbio);
#endif /* USE_GNUTLS */
			return 1;
		}

		if (verbose > 1)
		{
			fprintf(stderr, "%s: key for '%s' loaded\n",
			        progname, keyname);
		}

#ifdef USE_GNUTLS
		if (gnutls_x509_privkey_init(&xprivkey) != GNUTLS_E_SUCCESS)
		{
			fprintf(stderr,
			        "%s: gnutls_x509_privkey_init() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			return 1;
		}

		key.data = keydata;
		key.size = keylen;

		status = gnutls_x509_privkey_import(xprivkey, &key,
		                                    GNUTLS_X509_FMT_PEM);
		if (status != GNUTLS_E_SUCCESS)
		{
			status = gnutls_x509_privkey_import(xprivkey, &key,
		                                            GNUTLS_X509_FMT_DER);
		}

		if (status != GNUTLS_E_SUCCESS)
		{
			fprintf(stderr,
			        "%s: gnutls_x509_privkey_import() failed\n",
			        progname);
			(void) gnutls_x509_privkey_deinit(xprivkey);
			return -1;
		}

		status = gnutls_privkey_init(&privkey);
		if (status != GNUTLS_E_SUCCESS)
		{
			fprintf(stderr,
			        "%s: gnutls_privkey_init() failed\n",
			        progname);
			(void) gnutls_x509_privkey_deinit(xprivkey);
			return -1;
		}

		status = gnutls_privkey_import_x509(privkey, xprivkey, 0);
		if (status != GNUTLS_E_SUCCESS)
		{
			fprintf(stderr,
			        "%s: gnutls_privkey_import_x509() failed\n",
			        progname);
			(void) gnutls_x509_privkey_deinit(xprivkey);
			(void) gnutls_privkey_deinit(privkey);
			return -1;
		}
#else /* USE_GNUTLS */
		/* create a BIO for the private key */
		if (strncmp(keydata, "-----", 5) == 0)
		{
			private = BIO_new_mem_buf(keydata, keylen);
			if (private == NULL)
			{
				fprintf(stderr,
				        "%s: BIO_new_mem_buf() failed\n",
				        progname);
				(void) dkimf_db_close(db);
				(void) BIO_free(outbio);
				return 1;
			}

			pkey = PEM_read_bio_PrivateKey(private, NULL,
			                               NULL, NULL);
			if (pkey == NULL)
			{
				fprintf(stderr,
				        "%s: PEM_read_bio_PrivateKey() failed\n",
				        progname);
				(void) dkimf_db_close(db);
				(void) BIO_free(private);
				(void) BIO_free(outbio);
				return 1;
			}
		}
		else
		{
			int inlen;
			int outlen;
			BIO *b64;
			BIO *bio;
			BIO *decode;
			char buf[BUFRSZ];

			despace(keydata);

			b64 = BIO_new(BIO_f_base64());
			BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
			bio = BIO_new_mem_buf(keydata, -1);
			bio = BIO_push(b64, bio);

			decode = BIO_new(BIO_s_mem());

			for (;;)
			{
				inlen = BIO_read(bio, buf, sizeof buf);
				if (inlen == 0)
					break;
				BIO_write(decode, buf, inlen);
			}

			BIO_flush(decode);

			outlen = BIO_get_mem_data(decode, &p);
			memcpy(derdata, p, MIN(sizeof derdata, outlen));

			BIO_free_all(b64);
			BIO_free(decode);

			private = BIO_new_mem_buf(derdata, outlen);
			if (private == NULL)
			{
				fprintf(stderr,
				        "%s: BIO_new_mem_buf() failed\n",
				        progname);
				(void) dkimf_db_close(db);
				(void) BIO_free(outbio);
				return 1;
			}

			pkey = d2i_PrivateKey_bio(private, NULL);
			if (pkey == NULL)
			{
				fprintf(stderr,
				        "%s: d2i_PrivateKey_bio() failed\n",
				        progname);
				(void) dkimf_db_close(db);
				(void) BIO_free(private);
				(void) BIO_free(outbio);
				return 1;
			}
		}

		rsa = EVP_PKEY_get1_RSA(pkey);
		if (rsa == NULL)
		{
			fprintf(stderr,
			        "%s: EVP_PKEY_get1_RSA() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) BIO_free(private);
			(void) EVP_PKEY_free(pkey);
			(void) BIO_free(outbio);
			return 1;
		}

		/* convert private to public */
		status = PEM_write_bio_RSA_PUBKEY(outbio, rsa);
		if (status == 0)
		{
			fprintf(stderr,
			        "%s: PEM_write_bio_RSA_PUBKEY() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) BIO_free(private);
			(void) EVP_PKEY_free(pkey);
			(void) BIO_free(outbio);
			return 1;
		}
#endif /* USE_GNUTLS */

		/* write the record */
		if (nsupdate)
		{
			fprintf(out, "zone %s\n", domain);

			snprintf(tmpbuf, sizeof tmpbuf,
			         "update add %s%s%s%s%s %d TXT \"",
			         selector, suffix ? DKIMZONE : "",
			         fqdnsuffix ? "." : "",
			         fqdnsuffix ? domain : "",
			         fqdnsuffix ? "." : "",
			         ttl == -1 ? defttl : ttl);
		}
		else
		{
			if (ttl == -1)
			{
				snprintf(tmpbuf, sizeof tmpbuf,
				         "%s%s%s%s%s\tIN\tTXT\t( \"v=DKIM1; k=rsa; p=",
				         selector, suffix ? DKIMZONE : "",
				         fqdnsuffix ? "." : "",
				         fqdnsuffix ? domain : "",
				         fqdnsuffix ? "." : "");
			}
			else
			{
				snprintf(tmpbuf, sizeof tmpbuf,
				         "%s%s%s%s%s\t%d\tIN\tTXT\t( \"v=DKIM1; k=rsa; p=",
				         selector, suffix ? DKIMZONE : "",
				         fqdnsuffix ? "." : "",
				         fqdnsuffix ? domain : "",
				         fqdnsuffix ? "." : "",
				         ttl);
			}
		}

		fprintf(out, "%s", tmpbuf);

		if (nsupdate)
			olen = 0;
		else
			olen = strflen(tmpbuf);

		seenlf = FALSE;

#ifdef USE_GNUTLS
		if (gnutls_pubkey_init(&pubkey) != GNUTLS_E_SUCCESS)
		{
			fprintf(stderr, "%s: gnutls_pubkey_init() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) gnutls_x509_privkey_deinit(xprivkey);
			return 1;
		}

		if (gnutls_pubkey_import_privkey(pubkey,
		                                 privkey,
		                                 GNUTLS_KEY_DIGITAL_SIGNATURE,
		                                 0) != GNUTLS_E_SUCCESS)
		{
			fprintf(stderr,
			        "%s: gnutls_pubkey_import_privkey() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) gnutls_x509_privkey_deinit(xprivkey);
			(void) gnutls_pubkey_deinit(pubkey);
			return 1;
		}

		keylen = sizeof keydata;
		if (gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_PEM,
		                         keydata, &keylen) != GNUTLS_E_SUCCESS)
		{
			fprintf(stderr, "%s: gnutls_pubkey_export() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) gnutls_x509_privkey_deinit(xprivkey);
			return 1;
		}

		for (len = keylen, p = keydata; len > 0; len--, p++)
#else /* USE_GNUTLS */
		for (len = BIO_get_mem_data(outbio, &p); len > 0; len--, p++)
#endif /* USE_GNUTLS */
		{
			if (*p == '\n')
			{
				seenlf = TRUE;
			}
			else if (seenlf && *p == '-')
			{
				break;
			}
			else if (!seenlf)
			{
				continue;
			}
			else if (isascii(*p) && !isspace(*p))
			{
				if (olen >= MARGIN && !nsupdate)
				{
					fprintf(out, "\"\n\t\"");
					olen = 9;
				}
				else if (olen >= 255 && nsupdate)
				{
					fprintf(out, "\" \"");
					olen = 0;
				}

				(void) fputc(*p, out);
				olen++;
			}
		}

		if (nsupdate)
			fprintf(out, "\"\n");
		else
			fprintf(out, "\" )\n");

		/* prepare for the next one */
#ifdef USE_GNUTLS
		(void) gnutls_x509_privkey_deinit(xprivkey);
		(void) gnutls_privkey_deinit(privkey);
		(void) gnutls_pubkey_deinit(pubkey);
#else /* USE_GNUTLS */
		(void) BIO_reset(outbio);
#endif /* USE_GNUTLS */
	}

#ifndef USE_GNUTLS
	(void) BIO_flush(outbio);
	(void) BIO_free(outbio);
#endif /* ! USE_GNUTLS */
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
