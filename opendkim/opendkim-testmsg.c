/*
**  Copyright (c) 2011-2013, 2015, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <unistd.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include <dkim.h>

/* macros */
#ifndef FALSE
# define FALSE		0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* ! TRUE */

#define	BUFRSZ		1024
#define	DEFTMPDIR	"/tmp"
#define	CMDLINEOPTS	"Cd:Kk:s:t:"
#define STRORNULL(x)	((x) == NULL ? "(null)" : (x))
#define	TMPTEMPLATE	"dkimXXXXXX"

/* prototypes */
int usage(void);

/* globals */
char *progname;

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
	        "%s: usage: %s [options]\nValid options:\n"
	        "\t-C         \tpreserve CRLFs\n"
	        "\t-d domain  \tset signing domain\n"
	        "\t-K         \tkeep temporary files\n"
	        "\t-k keyfile \tprivate key file\n"
	        "\t-s selector\tset signing selector\n"
	        "\t-t path    \tdirectory for temporary files\n",
	        progname, progname);

	return EX_CONFIG;
}

/*
**  DECR -- remove CRs from a string
**
**  Parameters:
**  	str -- string to modify; must be NULL-terminated
**
**  Return value:
**  	None.
*/

void
decr(char *str)
{
	char *p;
	char *q;

	for (p = str, q = str; *p != '\0'; p++)
	{
		if (*p == '\r')
			continue;

		if (p != q)
			*q = *p;

		q++;
	}
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
	_Bool keepcrlf = FALSE;
	_Bool keepfiles = FALSE;
	_Bool testkey = FALSE;
	int c;
	int n = 0;
	int tfd;
	u_int flags;
	DKIM_STAT status;
	ssize_t rlen;
	ssize_t wlen;
	ssize_t l = (ssize_t) -1;
	dkim_alg_t sa = DKIM_SIGN_RSASHA1;
	dkim_canon_t bc = DKIM_CANON_SIMPLE;
	dkim_canon_t hc = DKIM_CANON_RELAXED;
	DKIM_LIB *lib;
	DKIM *dkim;
	char *p;
	const char *domain = NULL;
	const char *selector = NULL;
	const char *keyfile = NULL;
	char *keydata = NULL;
	char *tmpdir = DEFTMPDIR;
	char buf[BUFRSZ];
	char fn[BUFRSZ];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'C':
			keepcrlf = TRUE;
			break;

		  case 'd':
			domain = optarg;
			n++;
			break;

		  case 'K':
			keepfiles = TRUE;
			break;

		  case 'k':
			keyfile = optarg;
			n++;
			break;

		  case 's':
			selector = optarg;
			n++;
			break;

		  case 't':
			tmpdir = optarg;
			break;

		  default:
			return usage();
		}
	}

	if (n != 0 && n != 3)
		return usage();

	memset(fn, '\0', sizeof fn);
	snprintf(fn, sizeof fn, "%s/%s", tmpdir, TMPTEMPLATE);

	if (n == 3)
	{
		int fd;
		struct stat s;

		fd = open(keyfile, O_RDONLY);
		if (fd < 0)
		{
			fprintf(stderr, "%s: %s: open(): %s\n", progname,
			        keyfile, strerror(errno));
			return EX_OSERR;
		}

		if (fstat(fd, &s) != 0)
		{
			fprintf(stderr, "%s: %s: fstat(): %s\n", progname,
			        keyfile, strerror(errno));
			close(fd);
			return EX_OSERR;
		}

		keydata = malloc(s.st_size + 1);
		if (keydata == NULL)
		{
			fprintf(stderr, "%s: malloc(): %s\n", progname,
			        strerror(errno));
			close(fd);
			return EX_OSERR;
		}

		memset(keydata, '\0', s.st_size + 1);
		rlen = read(fd, keydata, s.st_size);
		if (rlen == -1)
		{
			fprintf(stderr, "%s: %s: read(): %s\n", progname,
			        keyfile, strerror(errno));
			close(fd);
			free(keydata);
			return EX_OSERR;
		}
		else if (rlen < s.st_size)
		{
			fprintf(stderr,
			        "%s: %s: read() truncated (got %lu, expected %lu)\n",
			        progname, keyfile, (unsigned long) rlen,
			        (unsigned long) s.st_size);
			close(fd);
			free(keydata);
			return EX_DATAERR;
		}

		close(fd);
	}

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
	{
		fprintf(stderr, "%s: dkim_init() failed\n", progname);
		return EX_SOFTWARE;
	}

	if (n == 0)
	{
		dkim = dkim_verify(lib, progname, NULL, &status);
		if (dkim == NULL)
		{
			fprintf(stderr, "%s: dkim_verify() failed: %s\n",
			        progname, dkim_getresultstr(status));
			dkim_close(lib);
			return EX_SOFTWARE;
		}
	}
	else
	{
		dkim = dkim_sign(lib, progname, NULL, keydata, selector,
		                 domain, hc, bc, sa, l, &status);
		if (dkim == NULL)
		{
			fprintf(stderr, "%s: dkim_sign() failed: %s\n",
			        progname, dkim_getresultstr(status));
			if (keydata != NULL)
				free(keydata);
			dkim_close(lib);
			return EX_SOFTWARE;
		}
	}

	/* set flags */
	flags = (DKIM_LIBFLAGS_FIXCRLF|DKIM_LIBFLAGS_STRICTHDRS);
	if (keepfiles)
		flags |= (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);

	tfd = mkstemp(fn);
	if (tfd < 0)
	{
		fprintf(stderr, "%s: mkstemp(): %s\n",
		        progname, strerror(errno));
		if (keydata != NULL)
			free(keydata);
		dkim_close(lib);
		return EX_SOFTWARE;
	}

	(void) unlink(fn);

	for (;;)
	{
		rlen = fread(buf, 1, sizeof buf, stdin);

		if (ferror(stdin))
		{
			fprintf(stderr, "%s: fread(): %s\n",
			        progname, strerror(errno));
			dkim_free(dkim);
			dkim_close(lib);
			close(tfd);
			if (keydata != NULL)
				free(keydata);
			return EX_SOFTWARE;
		}

		if (rlen > 0)
		{
			wlen = write(tfd, buf, rlen);
			if (wlen == -1)
			{
				fprintf(stderr, "%s: %s: write(): %s\n",
				        progname, fn, strerror(errno));
				dkim_free(dkim);
				dkim_close(lib);
				close(tfd);
				if (keydata != NULL)
					free(keydata);
				return EX_SOFTWARE;
			}

			status = dkim_chunk(dkim, buf, rlen);
			if (status != DKIM_STAT_OK)
			{
				fprintf(stderr, "%s: dkim_chunk(): %s\n",
				        progname, dkim_getresultstr(status));
				dkim_free(dkim);
				dkim_close(lib);
				close(tfd);
				if (keydata != NULL)
					free(keydata);
				return EX_SOFTWARE;
			}
		}

		if (feof(stdin))
			break;
	}

	status = dkim_chunk(dkim, NULL, 0);
	if (status != DKIM_STAT_OK)
	{
		fprintf(stderr, "%s: dkim_chunk(): %s\n",
		        progname, dkim_getresultstr(status));
		dkim_free(dkim);
		dkim_close(lib);
		close(tfd);
		if (keydata != NULL)
			free(keydata);
		return EX_SOFTWARE;
	}

	status = dkim_eom(dkim, &testkey);
	if (status != DKIM_STAT_OK)
	{
		fprintf(stderr, "%s: dkim_eom(): %s\n",
		        progname, dkim_getresultstr(status));
		dkim_free(dkim);
		dkim_close(lib);
		close(tfd);
		if (keydata != NULL)
			free(keydata);
		return EX_SOFTWARE;
	}

	if (n == 0)
	{
		/* XXX -- do a policy query */
	}
	else
	{
		unsigned char *sighdr;
		size_t siglen;

		/* extract signature */
		status = dkim_getsighdr_d(dkim,
		                          strlen(DKIM_SIGNHEADER),
		                          &sighdr, &siglen);
		if (status != DKIM_STAT_OK)
		{
			fprintf(stderr, "%s: dkim_getsighdr_d(): %s\n",
			        progname, dkim_getresultstr(status));
			dkim_free(dkim);
			dkim_close(lib);
			close(tfd);
			if (keydata != NULL)
				free(keydata);
			return EX_SOFTWARE;
		}

		/* print it and the message */
		if (!keepcrlf)
			decr(sighdr);
		fprintf(stdout, "%s: %s%s\n", DKIM_SIGNHEADER, sighdr,
		        keepcrlf ? "\r" : "");
		(void) lseek(tfd, 0, SEEK_SET);
		for (;;)
		{
			rlen = read(tfd, buf, sizeof buf);
			(void) fwrite(buf, 1, rlen, stdout);
			if (rlen < sizeof buf)
				break;
		}
	}

	dkim_free(dkim);
	dkim_close(lib);
	close(tfd);
	if (keydata != NULL)
		free(keydata);

	return EX_OK;
}
