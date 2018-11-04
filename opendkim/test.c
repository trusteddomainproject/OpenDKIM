/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2013, The Trusted Domain Project.  All rights reserved.
*/

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sysexits.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

/* libopendkim includes */
#include "build-config.h"
#include <dkim.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* libmilter includes */
#include <libmilter/mfapi.h>

/* opendkim includes */
#define DKIMF_MILTER_PROTOTYPES
#include "test.h"
#include "opendkim.h"

/* local types and definitions*/
#define	CRLF		"\r\n"

struct test_context
{
	void *	tc_priv;		/* private data pointer */
};

char *milter_status[] =
{
	"SMFIS_CONTINUE",
	"SMFIS_REJECT",
	"SMFIS_DISCARD",
	"SMFIS_ACCEPT",
	"SMFIS_TEMPFAIL"
};

char *envfrom[] =
{
	"<sender@example.org>",
	NULL
};

char *envrcpt[] =
{
	"<recipient@example.com>",
	NULL
};

#define	FCLOSE(x)		if ((x) != stdin) \
					fclose((x));
#define	MLFI_OUTPUT(x,y)	((y) > 1 || ((y) == 1 && (x) != SMFIS_CONTINUE))
#define	STRORNULL(x)		((x) == NULL ? "(null)" : (x))

/* globals */
static int tverbose = 0;

/*
**  DKIMF_TEST_SETPRIV -- store private pointer
**
**  Parameters:
**  	ctx -- context pointer
**  	ptr -- pointer to store
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_setpriv(void *ctx, void *ptr)
{
	struct test_context *tc;

	assert(ctx != NULL);

	tc = ctx;
	tc->tc_priv = ptr;

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_GETPRIV -- retrieve private pointer
**
**  Parameters:
**  	ctx -- context pointer
**
**  Return value:
**  	The private pointer.
*/

void *
dkimf_test_getpriv(void *ctx)
{
	struct test_context *tc;

	assert(ctx != NULL);

	tc = ctx;

	return tc->tc_priv;
}

/*
**  DKIMF_TEST_PROGRESS -- send progress message
**
**  Parameters:
**  	ctx -- context pointer
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_progress(void *ctx)
{
	assert(ctx != NULL);

	if (tverbose > 1)
		fprintf(stdout, "### PROGRESS\n");

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_SETREPLY -- set reply to use
**
**  Parameters:
**  	ctx -- context pointer
**  	rcode -- SMTP reply code
**  	xcode -- SMTP enhanced reply code
**  	replytxt -- SMTP reply text
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_setreply(void *ctx, char *rcode, char *xcode, char *replytxt)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### SETREPLY: rcode='%s' xcode='%s' replytxt='%s'\n",
		        STRORNULL(rcode), STRORNULL(xcode),
		        STRORNULL(replytxt));
	}

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_INSHEADER -- insert a header
**
**  Parameters:
**  	ctx -- context pointer
**  	idx -- insertion index
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_insheader(void *ctx, int idx, char *hname, char *hvalue)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### INSHEADER: idx=%d hname='%s' hvalue='%s'\n",
		        idx, STRORNULL(hname), STRORNULL(hvalue));
	}

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_CHGHEADER -- change a header
**
**  Parameters:
**  	ctx -- context pointer
**  	hname -- header name
**  	idx -- header index
**  	hvalue -- header value
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_chgheader(void *ctx, char *hname, int idx, char *hvalue)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### CHGHEADER: hname='%s' idx=%d hvalue='%s'\n",
		        STRORNULL(hname), idx, STRORNULL(hvalue));
	}

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_QUARANTINE -- request message quarantine
**
**  Parameters:
**  	ctx -- context pointer
**  	reason -- reason string
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_quarantine(void *ctx, char *reason)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### QUARANTINE: reason='%s'\n", STRORNULL(reason));
	}

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_ADDHEADER -- append a header
**
**  Parameters:
**  	ctx -- context pointer
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_addheader(void *ctx, char *hname, char *hvalue)
{
	assert(ctx != NULL);

	if (tverbose > 1)
	{
		fprintf(stdout,
		        "### ADDHEADER: hname='%s' hvalue='%s'\n",
		        STRORNULL(hname), STRORNULL(hvalue));
	}

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_DELRCPT -- request recipient delete
**
**  Parameters:
**  	ctx -- context pointer
**  	addr -- address
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_delrcpt(void *ctx, char *addr)
{
	assert(ctx != NULL);
	assert(addr != NULL);

	if (tverbose > 1)
		fprintf(stdout, "### DELRCPT: '%s'\n", addr);

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_ADDRCPT -- request recipient add
**
**  Parameters:
**  	ctx -- context pointer
**  	addr -- address
**
**  Return value:
**  	MI_SUCCESS
*/

int
dkimf_test_addrcpt(void *ctx, char *addr)
{
	assert(ctx != NULL);
	assert(addr != NULL);

	if (tverbose > 1)
		fprintf(stdout, "### ADDRCPT: '%s'\n", addr);

	return MI_SUCCESS;
}

/*
**  DKIMF_TEST_GETSYMVAL -- retrieve a symbol value
**
**  Parameters:
**  	ctx -- context pointer
**  	sym -- symbol name
**
**  Return value:
**  	Pointer to (static) string name.
**
**  Note:
**  	This isn't thread-safe, but test mode is single-threaded anyway.
**  	This is also a memory leak, but it's a short-lived test program
**  	anyway.
*/

char *
dkimf_test_getsymval(void *ctx, char *sym)
{
	static char symout[MAXBUFRSZ];

	assert(ctx != NULL);
	assert(sym != NULL);

	snprintf(symout, sizeof symout, "DEBUG-%s", sym);

	return strdup(symout);
}

/*
**  DKIMF_TESTFILE -- read a message and test it
**
**  Parameters:
**  	libopendkim -- DKIM_LIB handle
**  	file -- input file path
**  	fixedtime -- time to use on signatures (or -1)
**  	strict -- strict CRLF mode?
**  	verbose -- verbose level
**
**  Return value:
**  	An EX_* constant (see sysexits.h)
*/

static int
dkimf_testfile(DKIM_LIB *libopendkim, struct test_context *tctx,
               FILE *f, char *file, _Bool strict, int tverbose)
{
	bool inheaders = TRUE;
	bool newline = FALSE;
	int len = 0;
	int buflen = 0;
	int lineno = 0;
	int hslineno = 0;
	int c;
	DKIM_SIGINFO *sig;
	struct signreq *srlist = NULL;
	DKIM *dkim;
	char *p;
	sfsistat ms;
	char buf[MAXBUFRSZ];
	char line[MAXBUFRSZ];

	assert(libopendkim != NULL);
	assert(tctx != NULL);
	assert(f != NULL);

	memset(buf, '\0', sizeof buf);
	memset(line, '\0', sizeof buf);

	ms = mlfi_envfrom((SMFICTX *) tctx, envfrom);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: %s: mlfi_envfrom() returned %s\n",
		        progname, file, milter_status[ms]);
	}
	if (ms != SMFIS_CONTINUE)
		return EX_SOFTWARE;

	ms = mlfi_envrcpt((SMFICTX *) tctx, envrcpt);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: %s: mlfi_envrcpt() returned %s\n",
		        progname, file, milter_status[ms]);
	}
	if (ms != SMFIS_CONTINUE)
		return EX_SOFTWARE;

	while (!feof(f))
	{
		if (fgets(line, sizeof line, f) == NULL)
			break;

		lineno++;

		c = '\0';
		newline = FALSE;
		for (p = line; *p != '\0'; p++)
		{
			if (*p == '\n')
			{
				newline = TRUE;
				*p = '\0';
				break;
			}

			c = *p;
		}

		if (c != '\r')
		{
			if (strict)			/* error */
			{
				fprintf(stderr,
				        "%s: %s: line %d: not CRLF-terminated\n",
				        progname, file, lineno);
				return EX_DATAERR;
			}
		}
		else if (p != line)			/* eat the CR */
		{
			*(p - 1) = '\0';
		}

		if (inheaders)
		{
			if (line[0] == '\0')
			{
				if (buf[0] != '\0')
				{
					char *colon;

					colon = strchr(buf, ':');
					if (colon == NULL)
					{
						fprintf(stderr,
						        "%s: %s: line %d: header malformed\n",
						        progname, file,
						        lineno);
						return EX_DATAERR;
					}

					*colon = '\0';
					if (*(colon + 1) == ' ')
						colon++;

					ms = mlfi_header((SMFICTX *) tctx, buf,
					                 colon + 1);
					if (MLFI_OUTPUT(ms, tverbose))
					{
						fprintf(stderr,
						        "%s: %s: line %d: mlfi_header() returned %s\n",
						         progname, file,
						         hslineno,
						         milter_status[ms]);
					}

					if (ms != SMFIS_CONTINUE)
						return EX_SOFTWARE;
				}

				inheaders = FALSE;
				memset(buf, '\0', sizeof buf);
				memset(line, '\0', sizeof buf);

				ms = mlfi_eoh((SMFICTX *) tctx);
				if (MLFI_OUTPUT(ms, tverbose))
				{
					fprintf(stderr,
					        "%s: %s: mlfi_eoh() returned %s\n",
					         progname, file,
					         milter_status[ms]);
				}
				if (ms != SMFIS_CONTINUE)
					return EX_SOFTWARE;

				continue;
			}

			if (line[0] == ' ' || line[0] == '\t')
			{
				(void) strlcat(buf, CRLF, sizeof buf);

				if (strlcat(buf, line,
				            sizeof buf) >= sizeof buf)
				{
					fprintf(stderr,
					        "%s: %s: line %d: header '%*s...' too large\n",
					        progname, file, lineno,
					        20, buf);
					return EX_DATAERR;
				}
			}
			else
			{
				if (buf[0] != '\0')
				{
					char *colon;

					colon = strchr(buf, ':');
					if (colon == NULL)
					{
						fprintf(stderr,
						        "%s: %s: line %d: header malformed\n",
						        progname, file,
						        lineno);
						return EX_DATAERR;
					}

					*colon = '\0';
					if (*(colon + 1) == ' ')
						colon++;

					ms = mlfi_header((SMFICTX *) tctx, buf,
					                 colon + 1);
					if (MLFI_OUTPUT(ms, tverbose))
					{
						fprintf(stderr,
						        "%s: %s: line %d: mlfi_header() returned %s\n",
						        progname, file,
						        hslineno,
						        milter_status[ms]);
					}
					if (ms != SMFIS_CONTINUE)
						return EX_SOFTWARE;
					hslineno = 0;
				}

				if (hslineno == 0)
					hslineno = lineno;

				strlcpy(buf, line, sizeof buf);
			}
		}
		else
		{
			len = strlen(line);

			if (len + buflen >= (int) sizeof buf - 3)
			{
				ms = mlfi_body((SMFICTX *) tctx,
				               (u_char *) buf,
				               strlen(buf));
				if (MLFI_OUTPUT(ms, tverbose))
				{
					fprintf(stderr,
					        "%s: %s: mlfi_body() returned %s\n",
					        progname, file,
					        milter_status[ms]);
				}
				if (ms != SMFIS_CONTINUE)
					return EX_SOFTWARE;

				memset(buf, '\0', sizeof buf);
				buflen = 0;
			}

			memcpy(&buf[buflen], line, len);
			buflen += len;
			if (newline)
			{
				memcpy(&buf[buflen], CRLF, 2);
				buflen += 2;
			}
		}
	}

	/* unprocessed partial header? */
	if (inheaders && buf[0] != '\0')
	{
		char *colon;

		colon = strchr(buf, ':');
		if (colon == NULL)
		{
			fprintf(stderr,
			        "%s: %s: line %d: header malformed\n",
			        progname, file, lineno);
			return EX_DATAERR;
		}

		*colon = '\0';
		if (*(colon + 1) == ' ')
			colon++;

		ms = mlfi_header((SMFICTX *) tctx, buf, colon + 1);
		if (MLFI_OUTPUT(ms, tverbose))
		{
			fprintf(stderr,
			        "%s: %s: line %d: mlfi_header() returned %s\n",
			        progname, file, lineno, milter_status[ms]);
		}
		if (ms != SMFIS_CONTINUE)
			return EX_SOFTWARE;

		ms = mlfi_eoh((SMFICTX *) tctx);
		if (MLFI_OUTPUT(ms, tverbose))
		{
			fprintf(stderr,
			        "%s: %s: mlfi_eoh() returned %s\n",
			         progname, file, milter_status[ms]);
		}
		if (ms != SMFIS_CONTINUE)
			return EX_SOFTWARE;

		inheaders = FALSE;
		memset(buf, '\0', sizeof buf);
	}

	/* no headers found */
	if (inheaders)
	{
		fprintf(stderr, "%s: %s: warning: no headers on input\n",
		        progname, file);

		ms = mlfi_eoh((SMFICTX *) tctx);
		if (MLFI_OUTPUT(ms, tverbose))
		{
			fprintf(stderr, "%s: %s: mlfi_eoh() returned %s\n",
			        progname, file, milter_status[ms]);
		}
		if (ms != SMFIS_CONTINUE)
			return EX_SOFTWARE;
	}

	/* some body left */
	if (!inheaders && buf[0] != '\0')
	{
		ms = mlfi_body((SMFICTX *) tctx, (u_char *) buf, strlen(buf));
		if (MLFI_OUTPUT(ms, tverbose))
		{
			fprintf(stderr, "%s: %s: mlfi_body() returned %s\n",
			        progname, file, milter_status[ms]);
		}
		if (ms != SMFIS_CONTINUE)
			return EX_SOFTWARE;
	}

	ms = mlfi_eom((SMFICTX *) tctx);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: %s: mlfi_eom() returned %s\n",
		        progname, file, milter_status[ms]);
	}

	dkim = dkimf_getdkim(tctx->tc_priv);
	if (dkim != NULL)
	{
		int mode;

		mode = dkim_getmode(dkim);

		sig = dkim_getsignature(dkim);

		if (sig != NULL)
		{
			const u_char *domain;
			const u_char *selector;
			u_int flags;
			u_int bh;
			u_int keysize;

			domain = dkim_sig_getdomain(sig);
			selector = dkim_sig_getselector(sig);
			flags = dkim_sig_getflags(sig);
			bh = dkim_sig_getbh(sig);
			dkim_sig_getkeysize(sig, &keysize);

			if ((flags & DKIM_SIGFLAG_PASSED) != 0 &&
			    bh == DKIM_SIGBH_MATCH)
			{
				fprintf(stdout,
				        "%s: %s: verification (s=%s, d=%s, %d-bit key) succeeded\n",
				        progname, file, selector, domain,
				        keysize);
			}
			else
			{
				const char *err;
				int errcode;

				errcode = dkim_sig_geterror(sig);
				if (errcode == DKIM_SIGERROR_OK &&
				    bh == DKIM_SIGBH_MISMATCH)
					err = "body hash mismatch";
				else
					err = dkim_sig_geterrorstr(errcode);

				if (selector != NULL || domain != NULL)
				{
					char *dnssec;
					int dnsseccode = DKIM_DNSSEC_UNKNOWN;
				
					dnsseccode = dkim_sig_getdnssec(sig);

					switch (dnsseccode)
					{
					  case DKIM_DNSSEC_BOGUS:
						dnssec = "bogus";
						break;

					  case DKIM_DNSSEC_INSECURE:
						dnssec = "insecure";
						break;

					  case DKIM_DNSSEC_SECURE:
						dnssec = "secure";
						break;

					  case DKIM_DNSSEC_UNKNOWN:
					  default:
						dnssec = "unknown";
						break;
					}

					fprintf(stdout,
					        "%s: %s: verification (s=%s d=%s, %d-bit key, %s) failed: %s\n",
					        progname, file, selector,
					        domain, keysize, dnssec, err);
				}
				else
				{
					fprintf(stdout,
					        "%s: %s: verification failed: %s\n",
					        progname, file, err);
				}
			}
		}
		else if (sig == NULL && mode == DKIM_MODE_VERIFY)
		{
			fprintf(stdout, "%s: %s: message not signed\n",
			        progname, file);
		}
	}

	for (srlist = dkimf_getsrlist(tctx->tc_priv);
	     srlist != NULL;
	     srlist = srlist->srq_next)
	{
		dkim = srlist->srq_dkim;
		sig = dkim_getsignature(dkim);

		if (sig == NULL)
		{
			const char *err;

			err = dkim_geterror(dkim);
			if (err == NULL)
				err = "unknown error";

			fprintf(stdout, "%s: %s: no signature added: %s\n",
			        progname, file, err);
		}
		else
		{
			if (tverbose < 2)
			{
				DKIM_STAT status;
				size_t hlen;
				size_t rem;
				unsigned char hdr[DKIM_MAXHEADER + 1];

				hlen = strlen(DKIM_SIGNHEADER);
				rem = sizeof hdr - hlen - 2;
				memset(hdr, '\0', sizeof hdr);

				strlcpy((char *) hdr, DKIM_SIGNHEADER ": ",
				        sizeof hdr);

				status = dkim_getsighdr(dkim, hdr + hlen + 2,
				                        rem, hlen + 2);

				if (status != DKIM_STAT_OK)
				{
					fprintf(stderr,
					        "%s: %s: dkim_getsighdr(): %s\n",
					        progname, file,
					        dkim_getresultstr(status));
				}
				else
				{
					fprintf(stdout,
					        "%s: %s:\n%s\n",
					        progname, file, hdr);
				}
			}
		}
	}

	return EX_OK;
}

/*
**  DKIMF_TESTFILES -- test one or more input messages
**
**  Parameters:
**  	libopendkim -- DKIM_LIB handle
**  	flist -- input file list
**  	fixedtime -- time to use on signatures (or -1)
**  	strict -- strict CRLF mode?
**  	verbose -- verbose level
**
**  Return value:
**  	An EX_* constant (see sysexits.h)
*/

int
dkimf_testfiles(DKIM_LIB *libopendkim, char *flist, uint64_t fixedtime,
                bool strict, int verbose)
{
	char *file;
	char *ctx;
	FILE *f;
	int status;
	sfsistat ms;
	struct test_context *tctx;
	struct sockaddr_in sin;

	assert(libopendkim != NULL);
	assert(flist != NULL);

	tverbose = verbose;

	/* pass fixed signing time to the library */
	if (fixedtime != (uint64_t) -1)
	{
		(void) dkim_options(libopendkim, DKIM_OP_SETOPT,
		                    DKIM_OPTS_FIXEDTIME,
		                    &fixedtime, sizeof fixedtime);
	}

	/* set up a fake SMFICTX */
	tctx = (struct test_context *) malloc(sizeof(struct test_context));
	if (tctx == NULL)
	{
		fprintf(stderr, "%s: malloc(): %s\n", progname,
		        strerror(errno));
		return EX_OSERR;
	}
	tctx->tc_priv = NULL;

	(void) memset(&sin, '\0', sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(time(NULL) % 65536);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	ms = mlfi_connect((SMFICTX *) tctx, "localhost", (_SOCK_ADDR *) &sin);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: mlfi_connect() returned %s\n",
		        progname, milter_status[ms]);
	}
	if (ms != SMFIS_CONTINUE)
		return EX_SOFTWARE;

	/* loop through inputs */
	for (file = strtok_r(flist, ",", &ctx);
	     file != NULL;
	     file = strtok_r(NULL, ",", &ctx))
	{
		/* open the input */
		if (strcmp(file, "-") == 0)
		{
			f = stdin;
			file = "(stdin)";
		}
		else
		{
			f = fopen(file, "r");
			if (f == NULL)
			{
				fprintf(stderr, "%s: %s: fopen(): %s\n",
				        progname, file, strerror(errno));
				return EX_UNAVAILABLE;
			}
		}

		status = dkimf_testfile(libopendkim, tctx, f, file, strict,
		                        tverbose);

		FCLOSE(f);

		if (status != EX_OK)
			return status;
	}

	ms = mlfi_close((SMFICTX *) tctx);
	if (MLFI_OUTPUT(ms, tverbose))
	{
		fprintf(stderr, "%s: mlfi_close() returned %s\n",
		        progname, milter_status[ms]);
	}

	return EX_OK;
}
