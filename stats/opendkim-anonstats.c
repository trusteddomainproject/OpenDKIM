/*
**  Copyright (c) 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char opendkim_anonstats_c_id[] = "$Id$";
#endif /* ! lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* OpenDKIM includes */
#include "build-config.h"

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

/* macros, definitions */
#define	CMDLINEOPTS	"p:"

#define	MAXLINE		2048

/* globals */
char *progname;

/*
**  USAGE -- print usage message and exit
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
	fprintf(stderr, "%s: usage: %s [-p prefix] file\n", progname,
	        progname);

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
	int c;
	int n;
	int o;
	int nf;
	int line = 0;
	int nfields = 0;
	char *p;
	char *prefix = NULL;
	char *input = NULL;
	FILE *in;
	char **fields = NULL;
	char buf[MAXLINE + 1];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'p':
			if (prefix != NULL)
				return usage();
			prefix = optarg;
			break;

		  default:
			return usage();
		}
	}

	if (optind < argc - 1)
		return usage();
	else if (optind == argc - 1)
		input = argv[optind];

	if (input == NULL)
	{
		in = stdin;
	}
	else
	{
		in = fopen(input, "r");
		if (in == NULL)
		{
			fprintf(stderr, "%s: fopen(): %s\n", progname,
			        input);

			return EX_DATAERR;
		}
	}

	memset(buf, '\0', sizeof buf);

	while (fgets(buf, MAXLINE, in) != NULL)
	{
		line++;

		/* eat the newline */
		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n')
			{
				*p = '\0';
				break;
			}
		}

		/* first byte identifies the record type */
		c = buf[0];

		/* reset fields array */
		if (fields != NULL)
			memset(fields, '\0', sizeof(char *) * nfields);

		/* now break out the fields */
		n = 0;
		for (p = strtok(buf + 1, "\t");
		     p != NULL;
		     p = strtok(NULL, "\t"))
		{
			if (nfields == n)
			{
				int newnf;
				size_t newsz;
				char **new;

				newnf = MAX(nfields * 2, 8);
				newsz = sizeof(char *) * newnf;

				if (nfields == 0)
					new = (char **) malloc(newsz);
				else
					new = (char **) realloc(fields, newsz);

				if (new == NULL)
				{
					fprintf(stderr,
					        "%s: %salloc(): %s\n",
					        progname,
					        fields == NULL ? "m" : "re",
					        strerror(errno));
					return EX_OSERR;
				}

				nfields = newnf;
				fields = new;
			}

			fields[n++] = p;
		}

		/* dump it out, anonymizing as needed */
		fprintf(stdout, "%c", c);
		for (nf = 0; nf < n; nf++)
		{
			if ((c == 'M' && (nf == 2 || nf == 3)) ||
			    (c == 'S' && nf == 0))
			{
#ifdef USE_GNUTLS
				gnutls_hash_hd_t md5;
#else /* USE_GNUTLS */
				MD5_CTX md5;
#endif /* USE_GNUTLS */
				unsigned char *x;
				unsigned char dig[MD5_DIGEST_LENGTH];
				unsigned char tmp[MD5_DIGEST_LENGTH * 2 + 1];

#ifdef USE_GNUTLS
				if (gnutls_hash_init(&md5,
				                     GNUTLS_DIG_MD5) == 0)
				{
					if (prefix != NULL)
					{
						gnutls_hash(md5,
						            (void *) prefix,
						            strlen(prefix));
					}
					gnutls_hash(md5, fields[nf],
					            strlen(fields[nf]));
					gnutls_hash_deinit(md5, dig);
				}
#else /* USE_GNUTLS */
				MD5_Init(&md5);
				if (prefix != NULL)
				{
					MD5_Update(&md5, prefix,
					           strlen(prefix));
				}
				MD5_Update(&md5, fields[nf],
				           strlen(fields[nf]));
				MD5_Final(dig, &md5);
#endif /* USE_GNUTLS */

				memset(tmp, '\0', sizeof tmp);

				x = (u_char *) tmp;
				for (o = 0; o < MD5_DIGEST_LENGTH; o++)
				{
					snprintf((char *) x,
					         sizeof tmp - 2 * o,
					         "%02x", dig[o]);
					x += 2;
				}

				fprintf(stdout, "%s%s", nf == 0 ? "" : "\t",
				        tmp);
			}
			else
			{
				fprintf(stdout, "%s%s", nf == 0 ? "" : "\t",
				        fields[nf]);
			}
		}
		fprintf(stdout, "\n");
	}

	if (in != stdin)
		fclose(in);

	return EX_OK;
}
