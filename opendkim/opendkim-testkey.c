/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-testkey.c,v 1.1 2009/07/16 20:59:11 cm-msk Exp $
*/

#ifndef lint
static char dkim_testkey_c[] = "@(#)$Id: opendkim-testkey.c,v 1.1 2009/07/16 20:59:11 cm-msk Exp $";
#endif /* !lint */

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

/* openssl includes */
#include <openssl/err.h>

/* libsm includes */
#include <sm/string.h>

/* libdkim includes */
#include <dkim.h>
#include <dkim-test.h>

/* macros */
#define	CMDLINEOPTS	"d:k:s:"

/* prototypes */
void dkimf_log_ssl_errors(void);
int usage(void);

/* globals */
char *progname;

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
				sm_strlcat(errbuf, "; ", sizeof errbuf);
			sm_strlcat(errbuf, tmp, sizeof errbuf);
		}

		fprintf(stderr, "%s\n", errbuf);

		errno = saveerr;
	}
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
	        "\t-d domain  \tdomain name (required)\n"
	        "\t-k keypath \tpath to private key\n"
	        "\t-s selector\tselector name (required)\n",
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
	char *key = NULL;
	char *keypath = NULL;
	char *domain = NULL;
	char *selector = NULL;
	char *p;
	DKIM_LIB *lib;
	struct stat s;
	char err[BUFRSZ];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'd':
			domain = optarg;
			break;

		  case 'k':
			keypath = optarg;
			break;

		  case 's':
			selector = optarg;
			break;

		  default:
			return usage();
		}
	}

	if (domain == NULL || selector == NULL)
		return usage();

	ERR_load_crypto_strings();

	memset(&s, '\0', sizeof s);

	if (keypath != NULL)
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
			fprintf(stderr, "%s: %s: WARNING: unsafe permissions\n",
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
	}

	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
	{
		fprintf(stderr, "%s: dkim_init() failed\n", progname);
		(void) free(key);
		return EX_OSERR;
	}

	memset(err, '\0', sizeof err);

	status = dkim_test_key(lib, selector, domain, key, (size_t) s.st_size,
	                       err, sizeof err);

	(void) dkim_close(lib);

	switch (status)
	{
	  case -1:
		fprintf(stderr, "%s: %s\n", progname, err);
		dkimf_log_ssl_errors();
		return EX_UNAVAILABLE;

	  case 0:
		return EX_OK;

	  case 1:
		fprintf(stdout, "%s: %s\n", progname, err);
		dkimf_log_ssl_errors();
		return EX_DATAERR;
	}

	return 0;
}
