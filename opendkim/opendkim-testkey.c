/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2015, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* _REENTRANT */

/* system includes */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <assert.h>

#ifdef USE_GNUTLS
/* gcrypt includes */
# include <gnutls/gnutls.h>
#else /* USE_GNUTLS */
/* openssl includes */
# include <openssl/err.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include <dkim.h>
#include <dkim-test.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendkim includes */
#include "opendkim-db.h"
#include "opendkim-dns.h"
#include "config.h"
#include "opendkim-config.h"
#include "opendkim-crypto.h"

/* macros */
#define	CMDLINEOPTS	"d:k:s:vx:"
#define	DEFCONFFILE	CONFIG_BASE "/opendkim.conf"
#define	MAXBUFRSZ	65536
#define	BUFRSZ		2048

#ifndef MIN
# define MIN(x,y)	((x) < (y) ? (x) : (y))
#endif /* !MIN */

/* prototypes */
void dkimf_log_ssl_errors(void);
int usage(void);

/* globals */
char *progname;
#ifdef USE_UNBOUND
struct dkimf_unbound *unbound;			/* libunbound handle */
#endif /* USE_UNBOUND */

/*
**  DKIMF_LOG_SSL_ERRORS -- log any queued SSL library errors
**
**  Parameters:
**  	jobid -- job ID to include in log messages
**
**  Return value:
**  	None.
*/

void
dkimf_log_ssl_errors(void)
{
#ifdef USE_GNUTLS
	const char *err;

	err = dkimf_crypto_geterror();
	if (err != NULL)
		fprintf(stderr, "%s\n", err);
#else /* USE_GNUTLS */
	/* log any queued SSL error messages */
	if (ERR_peek_error() != 0)
	{
		int n;
		int saveerr;
		u_long e;
		char errbuf[BUFRSZ + 1];
		char tmp[BUFRSZ + 1];

		saveerr = errno;

		memset(errbuf, '\0', sizeof errbuf);
		for (n = 0; ; n++)
		{
			e = ERR_get_error();
			if (e == 0)
				break;

			memset(tmp, '\0', sizeof tmp);
			(void) ERR_error_string_n(e, tmp, sizeof tmp);
			if (n != 0)
				strlcat(errbuf, "; ", sizeof errbuf);
			strlcat(errbuf, tmp, sizeof errbuf);
		}

		fprintf(stderr, "%s\n", errbuf);

		errno = saveerr;
	}
#endif /* ! USE_GNUTLS */
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
**  USAGE -- print a usage message
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_CONFIG
*/

int
usage(void)
{
	fprintf(stderr,
	        "%s: usage: %s [options]\n"
	        "\t-d domain  \tdomain name\n"
	        "\t-k keypath \tpath to private key\n"
	        "\t-s selector\tselector name\n"
	        "\t-v         \tincrease verbose output\n"
	        "\t-x conffile\tconfiguration file\n",
	        progname, progname);

	return EX_CONFIG;
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
	int status;
	int fd;
	int len;
	int c;
	int verbose = 0;
	int argv_d = 0;
	int argv_s = 0;
	int argv_k = 0;
	int dnssec;
	char *key = NULL;
	char *dataset = NULL;
	char *nslist = NULL;
	char *conffile = NULL;
	char *p;
	DKIM_LIB *lib;
	char *trustanchor = NULL;
	char *nsconfig = NULL;
	struct stat s;
	char err[BUFRSZ];
	char domain[BUFRSZ];
	char selector[BUFRSZ];
	char keypath[MAXBUFRSZ];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	memset(domain, '\0', sizeof domain);
	memset(selector, '\0', sizeof selector);
	memset(keypath, '\0', sizeof keypath);

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'd':
			strlcpy(domain, optarg, sizeof domain);
			argv_d = 1;
			break;

		  case 'k':
			strlcpy(keypath, optarg, sizeof keypath);
			argv_k = 1;
			break;

		  case 's':
			strlcpy(selector, optarg, sizeof selector);
			argv_s = 1;
			break;

		  case 'v':
			verbose++;
			break;

		  case 'x':
			conffile = optarg;
			break;

		  default:
			return usage();
		}
	}

	/* process config file */
	if (conffile == NULL && access(DEFCONFFILE, R_OK) == 0)
	{
		conffile = DEFCONFFILE;
		if (verbose > 1)
		{
			fprintf(stderr, "%s: using default configfile %s\n",
			        progname, DEFCONFFILE);
		}
	}

	if (conffile != NULL)
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

		cfg = config_load(conffile, dkimf_config, &line,
		                  path, sizeof path, NULL);

		if (cfg == NULL)
		{
			fprintf(stderr,
			        "%s: %s: configuration error at line %u\n",
			        progname, path, line);
			return EX_CONFIG;
		}

		(void) config_get(cfg, "KeyTable", &dataset, sizeof dataset);

		if (domain[0] == '\0')
		{
			p = NULL;
			(void) config_get(cfg, "Domain", &p, sizeof p);
			if (p != NULL)
				strlcpy(domain, p, sizeof domain);
		}

		if (selector[0] == '\0')
		{
			p = NULL;
			(void) config_get(cfg, "Selector", &p, sizeof p);
			if (p != NULL)
				strlcpy(selector, p, sizeof selector);
		}

		if (keypath[0] == '\0')
		{
			p = NULL;
			(void) config_get(cfg, "KeyFile", &p, sizeof p);
			if (p != NULL)
				strlcpy(keypath, p, sizeof keypath);
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

		(void) config_get(cfg, "TrustAnchorFile",
		                  &trustanchor, sizeof trustanchor);

		(void) config_get(cfg, "ResolverConfiguration",
		                  &nsconfig, sizeof nsconfig);

		(void) config_get(cfg, "Nameservers",
		                  &nslist, sizeof nslist);
	}

	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
	{
		fprintf(stderr, "%s: dkim_init() failed\n", progname);
		(void) free(key);
		return EX_OSERR;
	}

#ifdef USE_UNBOUND
	(void) dkimf_unbound_setup(lib);
#endif /* USE_UNBOUND */

	if (dkim_dns_init(lib) != DKIM_STAT_OK)
	{
		fprintf(stderr, "%s: dkim_dns_init() failed\n", progname);
		(void) free(key);
		return EX_SOFTWARE;
	}

	if (nslist != NULL)
		status = dkimf_dns_setnameservers(lib, nslist);

	if (trustanchor != NULL)
	{
		status = dkimf_dns_trustanchor(lib, trustanchor);
		if (status != DKIM_STAT_OK)
		{
			fprintf(stderr,
			        "%s: failed to set trust anchor\n",
			        progname);

			(void) free(key);
			return EX_OSERR;
		}
	}

	if (nsconfig != NULL)
	{
		status = dkimf_dns_config(lib, nsconfig);
		if (status != DKIM_STAT_OK)
		{
			fprintf(stderr,
			        "%s: failed to set unbound configuration file\n",
			        progname);

			(void) free(key);
			return EX_OSERR;
		}
	}

	memset(err, '\0', sizeof err);

#ifndef USE_GNUTLS
	ERR_load_crypto_strings();
#endif /* ! USE_GNUTLS */

	/* process a KeyTable if specified and not overridden */
	if (dataset != NULL && argv_d == 0 && argv_k == 0 && argv_s == 0)
	{
		int c;
		int pass = 0;
		int fail = 0;
		size_t keylen;
		DKIMF_DB db;
		char keyname[BUFRSZ + 1];
		struct dkimf_db_data dbd[3];

		memset(dbd, '\0', sizeof dbd);

		status = dkimf_db_open(&db, dataset, DKIMF_DB_FLAG_READONLY,
		                       NULL, NULL);
		if (status != 0)
		{
			fprintf(stderr, "%s: dkimf_db_open() failed\n",
			        progname);
			return 1;
		}

		if (dkimf_db_type(db) == DKIMF_DB_TYPE_REFILE)
		{
			fprintf(stderr, "%s: invalid data set type\n",
			        progname);
			(void) dkimf_db_close(db);
			return 1;
		}

		for (c = 0; ; c++)
		{
			memset(keyname, '\0', sizeof keyname);
			memset(domain, '\0', sizeof domain);
			memset(selector, '\0', sizeof selector);
			memset(keypath, '\0', sizeof keypath);

			dbd[0].dbdata_buffer = domain;
			dbd[0].dbdata_buflen = sizeof domain;
			dbd[1].dbdata_buffer = selector;
			dbd[1].dbdata_buflen = sizeof selector;
			dbd[2].dbdata_buffer = keypath;
			dbd[2].dbdata_buflen = sizeof keypath;

			keylen = sizeof keyname;

			status = dkimf_db_walk(db, c == 0, keyname, &keylen,
			                       dbd, 3);
			if (status == -1)
			{
				fprintf(stderr,
				        "%s: dkimf_db_walk(%d) failed\n",
				        progname, c);
				(void) dkimf_db_close(db);
				return 1;
			}
			else if (status == 1)
			{
				(void) dkimf_db_close(db);
				break;
			}

			if (verbose > 1)
			{
				fprintf(stderr,
				        "%s: record %d for '%s' retrieved\n",
				        progname, c, keyname);
			}

			if (keypath[0] == '/' ||
			    strncmp(keypath, "./", 2) == 0 ||
			    strncmp(keypath, "../", 3) == 0)
			{
				status = stat(keypath, &s);
				if (status != 0)
				{
					fprintf(stderr,
					        "%s: %s: stat(): %s\n",
					        progname, keypath,
					        strerror(errno));
					return EX_OSERR;
				}

				if (!S_ISREG(s.st_mode))
				{
					fprintf(stderr,
					        "%s: %s: stat(): not a regular file\n",
					        progname, keypath);
					return EX_OSERR;
				}

				/* XXX -- should also check directories up the chain */
				if ((s.st_mode &
				     (S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) != 0)
				{
					fprintf(stderr,
					        "%s: %s: WARNING: unsafe permissions\n",
					        progname, keypath);
				}
			}

			keylen = sizeof keypath;
			if (!loadkey(keypath, &keylen))
			{
				fprintf(stderr,
				        "%s: load of key '%s' failed\n",
				        progname, keyname);
				(void) dkimf_db_close(db);
				return 1;
			}

			if (verbose > 1)
			{
				fprintf(stderr, "%s: checking key '%s'\n",
				        progname, keyname);
			}

			dnssec = DKIM_DNSSEC_UNKNOWN;

			status = dkim_test_key(lib, selector, domain,
			                       keypath, keylen, &dnssec,
			                       err, sizeof err);

			switch (status)
			{
			  case -1:
			  case 1:
				fprintf(stderr, "%s: key %s: %s\n", progname,
				        keyname, err);
				fail++;
				dkimf_log_ssl_errors();
				break;

			  case 0:
				if (verbose > 2)
				{
					fprintf(stdout, "%s: key %s: OK\n",
					        progname, keyname);
				}
				pass++;
				break;

			  default:
				assert(0);
			}

			switch (dnssec)
			{
			  case DKIM_DNSSEC_INSECURE:
				if (verbose > 0)
				{
					fprintf(stderr,
					        "%s: key %s not secure\n",
					        progname, keyname);
				}
				break;

			  case DKIM_DNSSEC_SECURE:
				if (verbose > 0)
				{
					fprintf(stderr,
					        "%s: key %s secure\n",
					        progname, keyname);
				}
				break;

			  case DKIM_DNSSEC_BOGUS:
				fprintf(stderr,
				        "%s: key %s bogus (DNSSEC failed)\n",
				        progname, keyname);
				break;

			  case DKIM_DNSSEC_UNKNOWN:
			  default:
				break;
			}
		}

		if (verbose > 0)
		{
			fprintf(stdout,
			        "%s: %d key%s checked; %d pass, %d fail\n",
			        progname, c, c == 1 ? "" : "s", pass, fail);
		}

		(void) dkim_close(lib);

		return 0;
	}

	if (domain[0] == '\0' || selector[0] == '\0')
		return usage();

	memset(&s, '\0', sizeof s);

	if (keypath[0] != '\0')
	{
		status = stat(keypath, &s);
		if (status != 0)
		{
			fprintf(stderr, "%s: %s: stat(): %s\n", progname,
			        keypath, strerror(errno));
			return EX_OSERR;
		}

		if (!S_ISREG(s.st_mode))
		{
			fprintf(stderr, "%s: %s: stat(): not a regular file\n",
			        progname, keypath);
			return EX_OSERR;
		}

		/* XXX -- should also check directories up the chain */
		if ((s.st_mode & (S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) != 0)
		{
			fprintf(stderr,
			        "%s: %s: WARNING: unsafe permissions\n",
			        progname, keypath);
		}

		key = malloc(s.st_size);
		if (key == NULL)
		{
			fprintf(stderr, "%s: malloc(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;
		}

		fd = open(keypath, O_RDONLY, 0);
		if (fd < 0)
		{
			fprintf(stderr, "%s: %s: open(): %s\n", progname,
			        keypath, strerror(errno));
			(void) free(key);
			return EX_OSERR;
		}

		len = read(fd, key, s.st_size);
		if (len < 0)
		{
			fprintf(stderr, "%s: %s: read(): %s\n", progname,
			        keypath, strerror(errno));
			(void) close(fd);
			(void) free(key);
			return EX_OSERR;
		}
		else if (len < s.st_size)
		{
			fprintf(stderr,
			        "%s: %s: read() truncated (expected %ld, got %d)\n",
			        progname, keypath, (long) s.st_size, len);
			(void) close(fd);
			(void) free(key);
			return EX_OSERR;
		}

		(void) close(fd);

		if (verbose > 1)
		{
			fprintf(stderr, "%s: key loaded from %s\n",
			        progname, keypath);
		}
	}

	dnssec = DKIM_DNSSEC_UNKNOWN;

	if (verbose > 1)
	{
		fprintf(stderr, "%s: checking key '%s._domainkey.%s'\n",
		        progname, selector, domain);
	}

	status = dkim_test_key(lib, selector, domain, key, (size_t) s.st_size,
	                       &dnssec, err, sizeof err);

	(void) dkim_close(lib);

	switch (dnssec)
	{
	  case DKIM_DNSSEC_INSECURE:
		if (verbose > 0)
			fprintf(stderr, "%s: key not secure\n", progname);
		break;

	  case DKIM_DNSSEC_SECURE:
		if (verbose > 0)
			fprintf(stderr, "%s: key secure\n", progname);
		break;

	  case DKIM_DNSSEC_BOGUS:
		fprintf(stderr, "%s: key bogus (DNSSEC failed)\n",
		        progname);
		break;

	  case DKIM_DNSSEC_UNKNOWN:
	  default:
		break;
	}

	switch (status)
	{
	  case -1:
		fprintf(stderr, "%s: %s\n", progname, err);
		dkimf_log_ssl_errors();
		return EX_UNAVAILABLE;

	  case 0:
		if (verbose > 2)
			fprintf(stdout, "%s: key OK\n", progname);
		return EX_OK;

	  case 1:
		fprintf(stdout, "%s: %s\n", progname, err);
		dkimf_log_ssl_errors();
		return EX_DATAERR;
	}

	return 0;
}
