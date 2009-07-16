/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char dkim_canon_c_id[] = "@(#)$Id: dkim-canon.c,v 1.1 2009/07/16 19:12:03 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>

/* libsm includes */
#include <sm/gen.h>
#include <sm/types.h>
#include <sm/cdefs.h>
#ifdef WITHOUT_LIBSM
# define sm_strlcat	strlcat
# define sm_strlcpy	strlcpy
#else /* WITHOUT_LIBSM */
# include <sm/string.h>
#endif /* WITHOUT_LIBSM */

/* libdkim includes */
#include "dkim.h"
#include "dkim-types.h"
#include "dkim-canon.h"
#include "dkim-util.h"
#include "util.h"

/* definitions */
#define	CRLF	"\r\n"
#define	SP	" "

/* macros */
#define	DKIM_ISLWSP(x)	((x) == 011 || (x) == 013 || (x) == 014 || (x) == 040)

/* prototypes */
extern void dkim_error __P((DKIM *, const char *, ...));

/* ========================= PRIVATE SECTION ========================= */

/*
**  DKIM_CANON_FREE -- destroy a canonicalization
**
**  Parameters:
**  	dkim -- DKIM handle
**  	canon -- canonicalization to destroy
**
**  Return value:
**  	None.
*/

static void
dkim_canon_free(DKIM *dkim, DKIM_CANON *canon)
{
	assert(dkim != NULL);
	assert(canon != NULL);

	if (canon->canon_hash != NULL)
	{
		switch (canon->canon_hashtype)
		{
		  case DKIM_HASHTYPE_SHA1:
		  {
			struct dkim_sha1 *sha1;

			sha1 = (struct dkim_sha1 *) canon->canon_hash;

			if (sha1->sha1_tmpbio != NULL)
			{
				BIO_free(sha1->sha1_tmpbio);
				sha1->sha1_tmpfd = -1;
				sha1->sha1_tmpbio = NULL;
			}

			break;
		  }

#ifdef DKIM_HASHTYPE_SHA256
		  case DKIM_HASHTYPE_SHA256:
		  {
			struct dkim_sha256 *sha256;

			sha256 = (struct dkim_sha256 *) canon->canon_hash;

			if (sha256->sha256_tmpbio != NULL)
			{
				BIO_free(sha256->sha256_tmpbio);
				sha256->sha256_tmpfd = -1;
				sha256->sha256_tmpbio = NULL;
			}

			break;
		  }
#endif /* DKIM_HASHTYPE_SHA256 */

		  default:
			assert(0);
			/* NOTREACHED */
		}

		dkim_mfree(dkim->dkim_libhandle, dkim->dkim_closure,
		           canon->canon_hash);
	}

	if (canon->canon_hashbuf != NULL)
	{
		dkim_mfree(dkim->dkim_libhandle, dkim->dkim_closure,
		           canon->canon_hashbuf);
	}

	dkim_mfree(dkim->dkim_libhandle, dkim->dkim_closure, canon);
}

/*
**  DKIM_CANON_WRITE -- write data to canonicalization stream(s)
**
**  Parameters:
**  	canon -- DKIM_CANON handle
**  	buf -- buffer containing canonicalized data
**  	buflen -- number of bytes to consume
**
**  Return value:
**  	None.
*/

static void
dkim_canon_write(DKIM_CANON *canon, u_char *buf, size_t buflen)
{
	assert(canon != NULL);

	if (canon->canon_remain != (off_t) -1)
		buflen = MIN(buflen, canon->canon_remain);

	if (buf == NULL || buflen == 0)
		return;

	assert(canon->canon_hash != NULL);

	switch (canon->canon_hashtype)
	{
	  case DKIM_HASHTYPE_SHA1:
	  {
		struct dkim_sha1 *sha1;

		sha1 = (struct dkim_sha1 *) canon->canon_hash;
		SHA1_Update(&sha1->sha1_ctx, buf, buflen);

		if (sha1->sha1_tmpbio != NULL)
			BIO_write(sha1->sha1_tmpbio, buf, buflen);

		break;
	  }

#ifdef SHA256_DIGEST_LENGTH
	  case DKIM_HASHTYPE_SHA256:
	  {
		struct dkim_sha256 *sha256;

		sha256 = (struct dkim_sha256 *) canon->canon_hash;
		SHA256_Update(&sha256->sha256_ctx, buf, buflen);

		if (sha256->sha256_tmpbio != NULL)
			BIO_write(sha256->sha256_tmpbio, buf, buflen);

		break;
	  }
#endif /*SHA256_DIGEST_LENGTH */
	}

	canon->canon_wrote += buflen;
	if (canon->canon_remain != (off_t) -1)
		canon->canon_remain -= buflen;
}

/*
**  DKIM_CANON_BUFFER -- buffer for dkim_canon_write()
**
**  Parameters:
**  	canon -- DKIM_CANON handle
**  	buf -- buffer containing canonicalized data
**  	buflen -- number of bytes to consume
**
**  Return value:
**  	None.
*/

static void
dkim_canon_buffer(DKIM_CANON *canon, u_char *buf, size_t buflen)
{
	assert(canon != NULL);

	/* NULL buffer or 0 length means flush */
	if (buf == NULL || buflen == 0)
	{
		if (canon->canon_hashbuflen > 0)
		{
			dkim_canon_write(canon, canon->canon_hashbuf,
			                 canon->canon_hashbuflen);
			canon->canon_hashbuflen = 0;
		}
		return;
	}

	/* not enough buffer space; write the buffer out */
	if (canon->canon_hashbuflen + buflen > canon->canon_hashbufsize)
	{
		dkim_canon_write(canon, canon->canon_hashbuf,
		                 canon->canon_hashbuflen);
		canon->canon_hashbuflen = 0;
	}

	/*
	**  Now, if the input is bigger than the buffer, write it too;
	**  otherwise cache it.
	*/

	if (buflen >= canon->canon_hashbufsize)
	{
		dkim_canon_write(canon, buf, buflen);
	}
	else
	{
		memcpy(&canon->canon_hashbuf[canon->canon_hashbuflen],
		       buf, buflen);
		canon->canon_hashbuflen += buflen;
	}
}

/*
**  DKIM_CANON_HEADER -- canonicalize a header and write it
**
**  Parameters:
**  	dkim -- DKIM handle
**  	canon -- DKIM_CANON handle
**  	hdr -- header handle
**  	crlf -- write a CRLF at the end?
**
**  Return value:
**  	A DKIM_STAT constant.
*/

static DKIM_STAT
dkim_canon_header(DKIM *dkim, DKIM_CANON *canon, struct dkim_header *hdr,
                  bool crlf)
{
	bool space;
	int n;
	u_char *p;
	u_char *tmp;
	u_char *end;
	u_char tmpbuf[BUFRSZ];

	assert(canon != NULL);
	assert(hdr != NULL);

	tmp = tmpbuf;
	end = tmpbuf + sizeof tmpbuf - 1;

	if (dkim->dkim_canonbuf == NULL)
	{
		dkim->dkim_canonbuf = dkim_dstring_new(dkim, hdr->hdr_textlen,
		                                       0);
		if (dkim->dkim_canonbuf == NULL)
			return DKIM_STAT_NORESOURCE;
	}
	else
	{
		dkim_dstring_blank(dkim->dkim_canonbuf);
	}

	n = 0;

	dkim_canon_buffer(canon, NULL, 0);

	switch (canon->canon_canon)
	{
	  case DKIM_CANON_SIMPLE:
		if (!dkim_dstring_catn(dkim->dkim_canonbuf,
		                       hdr->hdr_text, hdr->hdr_textlen) ||
		    (crlf && !dkim_dstring_catn(dkim->dkim_canonbuf, CRLF, 2)))
			return DKIM_STAT_NORESOURCE;
		break;

	  case DKIM_CANON_RELAXED:
		/* process header field name (before colon) first */
		for (p = hdr->hdr_text; *p != '\0'; p++)
		{
			/*
			**  Discard spaces before the colon or before the end
			**  of the first word.
			*/

			if (isascii(*p))
			{
				/* discard spaces */
				if (isspace(*p))
					continue;

				/* convert to lowercase */
				if (isupper(*p))
					*tmp++ = tolower(*p);
				else
					*tmp++ = *p;
			}
			else
			{
				*tmp++ = *p;
			}

			/* reaching the end of the cache buffer, flush it */
			if (tmp == end)
			{
				*tmp = '\0';

				if (!dkim_dstring_catn(dkim->dkim_canonbuf,
				                       tmpbuf, tmp - tmpbuf))
					return DKIM_STAT_NORESOURCE;

				tmp = tmpbuf;
			}
			
			if (*p == ':')
			{
				p++;
				break;
			}
		}

		/* skip all spaces before first word */
		while (*p != '\0' && isascii(*p) && isspace(*p))
			p++;

		space = FALSE;				/* just saw a space */

		for ( ; *p != '\0'; p++)
		{
			if (isascii(*p) && isspace(*p))
			{
				/* mark that there was a space and continue */
				space = TRUE;

				continue;
			}

			/*
			**  Any non-space marks the beginning of a word.
			**  If there's a stored space, use it up.
			*/

			if (space)
			{
				*tmp++ = ' ';

				/* flush buffer? */
				if (tmp == end)
				{
					*tmp = '\0';

					if (!dkim_dstring_catn(dkim->dkim_canonbuf,
					                       tmpbuf,
					                       tmp - tmpbuf))
						return DKIM_STAT_NORESOURCE;

					tmp = tmpbuf;
				}

				space = FALSE;
			}

			/* copy the byte */
			*tmp++ = *p;

			/* flush buffer? */
			if (tmp == end)
			{
				*tmp = '\0';

				if (!dkim_dstring_catn(dkim->dkim_canonbuf,
				                       tmpbuf, tmp - tmpbuf))
					return DKIM_STAT_NORESOURCE;

				tmp = tmpbuf;
			}
		}

		/* flush any cached data */
		if (tmp != tmpbuf)
		{
			*tmp = '\0';

			if (!dkim_dstring_catn(dkim->dkim_canonbuf,
			                       tmpbuf, tmp - tmpbuf))
				return DKIM_STAT_NORESOURCE;
		}

		if (crlf && !dkim_dstring_catn(dkim->dkim_canonbuf, CRLF, 2))
			return DKIM_STAT_NORESOURCE;

		break;
	}

	dkim_canon_buffer(canon, dkim_dstring_get(dkim->dkim_canonbuf),
	                  dkim_dstring_len(dkim->dkim_canonbuf));

	return DKIM_STAT_OK;
}

/*
**  DKIM_CANON_FLUSHBLANKS -- use accumulated blank lines in canonicalization
**
**  Parameters:
**  	canon -- DKIM_CANON handle
**
**  Return value:
**  	None.
*/

static void
dkim_canon_flushblanks(DKIM_CANON *canon)
{
	int c;

	assert(canon != NULL);

	for (c = 0; c < canon->canon_blanks; c++)
		dkim_canon_buffer(canon, CRLF, 2);
	canon->canon_blanks = 0;
}

/*
**  DKIM_CANON_SELECTHDRS -- choose headers to be included in canonicalization
**
**  Parameters:
**  	dkim -- DKIM context in which this is performed
**  	hdrlist -- string containing headers that should be marked, separated
**  	           by the ":" character
**  	ptrs -- array of header pointers (modified)
**  	nptr -- number of pointers available at "ptrs"
**
**  Return value:
**  	Count of headers added to "ptrs", or -1 on error.
**
**  Notes:
**  	Selects headers to be passed to canonicalization and the order in
**  	which this is done.  "ptrs" is populated by pointers to headers
**  	in the order in which they should be fed to canonicalization.
**
**  	If any of the returned pointers is NULL, then a header named by
**  	"hdrlist" was not found.
*/

static int
dkim_canon_selecthdrs(DKIM *dkim, u_char *hdrlist, struct dkim_header **ptrs,
                      int nptrs)
{
	int c;
	int n;
	int m;
	int shcnt;
	size_t len;
	u_char *bar;
	char *ctx;
	char *colon;
	struct dkim_header *hdr;
	struct dkim_header **lhdrs;
	u_char **hdrs;

	assert(dkim != NULL);
	assert(ptrs != NULL);
	assert(nptrs != 0);

	/* if there are no headers named, use them all */
	if (hdrlist == NULL)
	{
		n = 0;

		for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (n >= nptrs)
			{
				dkim_error(dkim, "too many headers (max %d)",
				           nptrs);
				return -1;
			}
			ptrs[n] = hdr;
			n++;
		}

		return n;
	}

	if (dkim->dkim_hdrlist == NULL)
	{
		dkim->dkim_hdrlist = dkim_malloc(dkim->dkim_libhandle,
		                                 dkim->dkim_closure,
		                                 DKIM_MAXHEADER);
		if (dkim->dkim_hdrlist == NULL)
		{
			dkim_error(dkim, "unable to allocate %d bytes(s)",
			           DKIM_MAXHEADER);

			return -1;
		}
	}

	sm_strlcpy(dkim->dkim_hdrlist, hdrlist, DKIM_MAXHEADER);

	/* mark all headers as not used */
	for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
		hdr->hdr_flags &= ~DKIM_HDR_SIGNED;

	n = dkim->dkim_hdrcnt * sizeof(struct dkim_header *);
	lhdrs = DKIM_MALLOC(dkim, n);
	if (lhdrs == NULL)
		return -1;
	memset(lhdrs, '\0', n);

	shcnt = 1;
	for (colon = dkim->dkim_hdrlist; *colon != '\0'; colon++)
	{
		if (*colon == ':')
			shcnt++;
	}
	n = sizeof(u_char *) * shcnt;
	hdrs = DKIM_MALLOC(dkim, n);
	if (hdrs == NULL)
		return -1;
	memset(hdrs, '\0', n);

	n = 0;

	/* make a split-out copy of hdrlist */
	for (bar = strtok_r(dkim->dkim_hdrlist, ":", &ctx);
	     bar != NULL;
	     bar = strtok_r(NULL, ":", &ctx))
	{
		hdrs[n] = (u_char *) bar;
		n++;
	}

	/* for each named header, find the last unused one and use it up */
	shcnt = 0;
	for (c = 0; c < n; c++)
	{
		lhdrs[shcnt] = NULL;

		len = MIN(DKIM_MAXHEADER, strlen(hdrs[c]));
		while (len > 0 &&
		       isascii(hdrs[c][len - 1]) &&
		       isspace(hdrs[c][len - 1]))
			len--;

		for (hdr = dkim->dkim_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (hdr->hdr_flags & DKIM_HDR_SIGNED)
				continue;

			if (len == hdr->hdr_namelen &&
			    strncasecmp(hdr->hdr_text, hdrs[c], len) == 0)
				lhdrs[shcnt] = hdr;
		}

		if (lhdrs[shcnt] != NULL)
		{
			lhdrs[shcnt]->hdr_flags |= DKIM_HDR_SIGNED;
			shcnt++;
		}
	}

	/* bounds check */
	if (shcnt > nptrs)
	{
		dkim_error(dkim, "too many headers (found %d, max %d)", shcnt,
		           nptrs);

		DKIM_FREE(dkim, lhdrs);
		DKIM_FREE(dkim, hdrs);

		return -1;
	}

	/* copy to the caller's buffers */
	m = 0;
	for (c = 0; c < shcnt; c++)
	{
		if (lhdrs[c] != NULL)
		{
			ptrs[m] = lhdrs[c];
			m++;
		}
	}

	DKIM_FREE(dkim, lhdrs);
	DKIM_FREE(dkim, hdrs);

	return m;
}

/*
**  DKIM_CANON_FIXCRLF -- rebuffer a body chunk, fixing "naked" CRs and LFs
**
**  Parameters:
**  	dkim -- DKIM handle
**  	canon -- canonicalization being handled
**  	buf -- buffer to be fixed
**  	buflen -- number of bytes at "buf"
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Side effects:
**  	dkim->dkim_canonbuf will be initialized and used.
*/

static DKIM_STAT
dkim_canon_fixcrlf(DKIM *dkim, DKIM_CANON *canon, u_char *buf, size_t buflen)
{
	u_char prev;
	u_char *p;
	u_char *eob;

	assert(dkim != NULL);
	assert(canon != NULL);
	assert(buf != NULL);

	if (dkim->dkim_canonbuf == NULL)
	{
		dkim->dkim_canonbuf = dkim_dstring_new(dkim, buflen, 0);
		if (dkim->dkim_canonbuf == NULL)
			return DKIM_STAT_NORESOURCE;
	}
	else
	{
		dkim_dstring_blank(dkim->dkim_canonbuf);
	}

	eob = buf + buflen - 1;

	prev = canon->canon_lastchar;

	for (p = buf; p <= eob; p++)
	{
		if (*p == '\n' && prev != '\r')
		{
			dkim_dstring_catn(dkim->dkim_canonbuf, CRLF, 2);
		}
		else if (*p == '\r' && p < eob && *(p + 1) != '\n')
		{
			dkim_dstring_catn(dkim->dkim_canonbuf, CRLF, 2);
		}
		else
		{
			dkim_dstring_cat1(dkim->dkim_canonbuf, *p);
		}

		prev = *p;
	}

	return DKIM_STAT_OK;
}


/* ========================= PUBLIC SECTION ========================= */

/*
**  DKIM_CANON_INIT -- initialize all canonicalizations
**
**  Parameters:
**  	dkim -- DKIM handle
**  	tmp -- make temp files?
**  	keep -- keep temp files?
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_canon_init(DKIM *dkim, bool tmp, bool keep)
{
	int fd;
	DKIM_STAT status;
	DKIM_CANON *cur;

	assert(dkim != NULL);

	for (cur = dkim->dkim_canonhead; cur != NULL; cur = cur->canon_next)
	{
		cur->canon_hashbuf = DKIM_MALLOC(dkim, DKIM_HASHBUFSIZE);
		if (cur->canon_hashbuf == NULL)
		{
			dkim_error(dkim,
			           "unable to allocate %d byte(s)",
			           sizeof(struct dkim_sha1));
			return DKIM_STAT_NORESOURCE;
		}
		cur->canon_hashbufsize = DKIM_HASHBUFSIZE;
		cur->canon_hashbuflen = 0;

		switch (cur->canon_hashtype)
		{
		  case DKIM_HASHTYPE_SHA1:
		  {
			struct dkim_sha1 *sha1;

			sha1 = (struct dkim_sha1 *) DKIM_MALLOC(dkim,
			                                        sizeof(struct dkim_sha1));
			if (sha1 == NULL)
			{
				dkim_error(dkim,
				           "unable to allocate %d byte(s)",
				           sizeof(struct dkim_sha1));
				return DKIM_STAT_NORESOURCE;
			}

			memset(sha1, '\0', sizeof(struct dkim_sha1));
			SHA1_Init(&sha1->sha1_ctx);

			if (tmp)
			{
				status = dkim_tmpfile(dkim, &fd, keep);
				if (status != DKIM_STAT_OK)
				{
					DKIM_FREE(dkim, sha1);
					return status;
				}

				sha1->sha1_tmpfd = fd;
				sha1->sha1_tmpbio = BIO_new_fd(fd, 1);
			}

			cur->canon_hash = sha1;

		  	break;
		  }

#ifdef DKIM_HASHTYPE_SHA256
		  case DKIM_HASHTYPE_SHA256:
		  {
			struct dkim_sha256 *sha256;

			sha256 = (struct dkim_sha256 *) DKIM_MALLOC(dkim,
			                                            sizeof(struct dkim_sha256));
			if (sha256 == NULL)
			{
				dkim_error(dkim,
				           "unable to allocate %d byte(s)",
				           sizeof(struct dkim_sha256));
				return DKIM_STAT_NORESOURCE;
			}

			memset(sha256, '\0', sizeof(struct dkim_sha256));
			SHA256_Init(&sha256->sha256_ctx);

			if (tmp)
			{
				status = dkim_tmpfile(dkim, &fd, keep);
				if (status != DKIM_STAT_OK)
				{
					DKIM_FREE(dkim, sha256);
					return status;
				}

				sha256->sha256_tmpfd = fd;
				sha256->sha256_tmpbio = BIO_new_fd(fd, 1);
			}

			cur->canon_hash = sha256;

		  	break;
		  }
#endif /* DKIM_HASHTYPE_SHA256 */

		  default:
			assert(0);
		}
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_CANON_CLEANUP -- discard canonicalizations
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	None.
*/

void
dkim_canon_cleanup(DKIM *dkim)
{
	DKIM_CANON *cur;
	DKIM_CANON *next;

	assert(dkim != NULL);

	cur = dkim->dkim_canonhead;
	while (cur != NULL)
	{
		next = cur->canon_next;

		dkim_canon_free(dkim, cur);

		cur = next;
	}

	dkim->dkim_canonhead = NULL;
}

/*
**  DKIM_ADD_CANON -- add a new canonicalization handle if needed
**
**  Parameters:
**  	dkim -- verification handle
**  	hdr -- TRUE iff this is specifying a header canonicalization
**  	canon -- canonicalization mode
**  	hashtype -- hash type
**  	hdrlist -- for header canonicalization, the header list
**  	hdr -- pointer to header being verified (NULL for signing)
**  	length -- for body canonicalization, the length limit (-1 == all)
**  	cout -- DKIM_CANON handle (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_add_canon(DKIM *dkim, bool hdr, dkim_canon_t canon, int hashtype,
               u_char *hdrlist, struct dkim_header *sighdr,
               off_t length, DKIM_CANON **cout)
{
	DKIM_CANON *cur;
	DKIM_CANON *new;

	assert(dkim != NULL);
	assert(canon == DKIM_CANON_SIMPLE || canon == DKIM_CANON_RELAXED);
#ifdef DKIM_HASHTYPE_SHA256
	assert(hashtype == DKIM_HASHTYPE_SHA1 ||
	       hashtype == DKIM_HASHTYPE_SHA256);
#else /* DKIM_HASHTYPE_SHA256 */
	assert(hashtype == DKIM_HASHTYPE_SHA1);
#endif /* DKIM_HASHTYPE_SHA256 */

	if (!hdr)
	{
		for (cur = dkim->dkim_canonhead; cur != NULL; cur = cur->canon_next)
		{
			if (cur->canon_hdr ||
			    cur->canon_hashtype != hashtype ||
			    cur->canon_canon != canon)
				continue;

			if (length != cur->canon_length)
				continue;

			if (cout != NULL)
				*cout = cur;

			return DKIM_STAT_OK;
		}
	}

	new = (DKIM_CANON *) dkim_malloc(dkim->dkim_libhandle,
	                                 dkim->dkim_closure, sizeof *new);
	if (new == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)", sizeof *new);
		return DKIM_STAT_NORESOURCE;
	}

	new->canon_done = FALSE;
	new->canon_hdr = hdr;
	new->canon_canon = canon;
	new->canon_hashtype = hashtype;
	new->canon_hash = NULL;
	new->canon_wrote = 0;
	if (hdr)
	{
		new->canon_length = (off_t) -1;
		new->canon_remain = (off_t) -1;
	}
	else
	{
		new->canon_length = length;
		new->canon_remain = length;
	}
	new->canon_sigheader = sighdr;
	new->canon_hdrlist = hdrlist;
	new->canon_next = NULL;
	new->canon_done = FALSE;
	new->canon_blankline = FALSE;
	new->canon_blanks = 0;
	new->canon_wrote = 0;
	new->canon_hashbuflen = 0;
	new->canon_hashbufsize = 0;
	new->canon_hashbuf = NULL;
	new->canon_lastchar = '\0';

	if (dkim->dkim_canonhead == NULL)
	{
		dkim->dkim_canontail = new;
		dkim->dkim_canonhead = new;
	}
	else
	{
		dkim->dkim_canontail->canon_next = new;
		dkim->dkim_canontail = new;
	}

	if (cout != NULL)
		*cout = new;

	return DKIM_STAT_OK;
}

/*
**  DKIM_CANON_RUNHEADERS -- run the headers through all header
**                           canonicalizations
**
**  Parameters:
**  	dkim -- DKIM handle
**  	signing -- TRUE iff we're signing
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Note:
**  	Header canonicalizations are finalized by this function when
**  	verifying.  In signing mode, header canonicalizations are finalized
**  	by a subsequent call to dkim_canon_signature().
*/

DKIM_STAT
dkim_canon_runheaders(DKIM *dkim, bool signing)
{
	u_char savechar;
	int c;
	int n;
	int in;
	int nhdrs;
	int last = '\0';
	DKIM_STAT status;
	u_char *tmp;
	u_char *end;
	DKIM_CANON *cur;
	u_char *p;
	struct dkim_header *hdr;
	struct dkim_header **hdrset;
	struct dkim_header tmphdr;
	u_char tmpbuf[BUFRSZ];

	assert(dkim != NULL);

	tmp = tmpbuf;
	end = tmpbuf + sizeof tmpbuf - 1;

	n = dkim->dkim_hdrcnt * sizeof(struct dkim_header *);
	hdrset = DKIM_MALLOC(dkim, n);
	if (hdrset == NULL)
		return DKIM_STAT_NORESOURCE;

	if (dkim->dkim_hdrbuf == NULL)
	{
		dkim->dkim_hdrbuf = dkim_dstring_new(dkim, BUFRSZ, MAXBUFRSZ);
		if (dkim->dkim_hdrbuf == NULL)
		{
			DKIM_FREE(dkim, hdrset);
			return DKIM_STAT_NORESOURCE;
		}
	}
	else
	{
		dkim_dstring_blank(dkim->dkim_hdrbuf);
	}

	for (cur = dkim->dkim_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done || !cur->canon_hdr)
			continue;

		/* clear header selection flags if verifying */
		if (!signing)
		{
			if (cur->canon_hdrlist == NULL)
			{
				for (hdr = dkim->dkim_hhead;
				     hdr != NULL;
				     hdr = hdr->hdr_next)
					hdr->hdr_flags |= DKIM_HDR_SIGNED;
			}
			else
			{
				for (hdr = dkim->dkim_hhead;
				     hdr != NULL;
				     hdr = hdr->hdr_next)
					hdr->hdr_flags &= ~DKIM_HDR_SIGNED;

				memset(hdrset, '\0', n);

				/* do header selection */
				nhdrs = dkim_canon_selecthdrs(dkim,
				                              cur->canon_hdrlist,
				                              hdrset,
				                              dkim->dkim_hdrcnt);

				if (nhdrs == -1)
				{
					dkim_error(dkim,
					           "dkim_canon_selecthdrs() failed during canonicalization");
					DKIM_FREE(dkim, hdrset);
					return DKIM_STAT_INTERNAL;
				}
			}
		}
		else
		{
			DKIM_LIB *lib;

			lib = dkim->dkim_libhandle;

			memset(hdrset, '\0', sizeof hdrset);
			nhdrs = 0;

			/* tag headers to be signed */
			for (hdr = dkim->dkim_hhead;
			     hdr != NULL && nhdrs < MAXHEADERS;
			     hdr = hdr->hdr_next)
			{
				if (!lib->dkiml_signre)
				{
					tmp = dkim_dstring_get(dkim->dkim_hdrbuf);

					if (tmp[0] != '\0')
					{
						dkim_dstring_cat1(dkim->dkim_hdrbuf,
						                 ':');
					}

					dkim_dstring_catn(dkim->dkim_hdrbuf,
					                  hdr->hdr_text,
					                  hdr->hdr_namelen);
					continue;
				}

				/* could be space, could be colon ... */
				savechar = hdr->hdr_text[hdr->hdr_namelen];

				/* terminate the header field name and test */
				hdr->hdr_text[hdr->hdr_namelen] = '\0';
				status = regexec(&lib->dkiml_hdrre,
				                 hdr->hdr_text, 0, NULL, 0);

				/* restore the character */
				hdr->hdr_text[hdr->hdr_namelen] = savechar;

				if (status == 0)
				{
					tmp = dkim_dstring_get(dkim->dkim_hdrbuf);

					if (tmp[0] != '\0')
					{
						dkim_dstring_cat1(dkim->dkim_hdrbuf,
						                 ':');
					}

					dkim_dstring_catn(dkim->dkim_hdrbuf,
					                  hdr->hdr_text,
							  hdr->hdr_namelen);
				}
				else
				{
					assert(status == REG_NOMATCH);
				}
			}

			memset(hdrset, '\0', n);

			/* do header selection */
			nhdrs = dkim_canon_selecthdrs(dkim,
			                              dkim_dstring_get(dkim->dkim_hdrbuf),
			                              hdrset,
			                              dkim->dkim_hdrcnt);

			if (nhdrs == -1)
			{
				dkim_error(dkim,
				           "dkim_canon_selecthdrs() failed during canonicalization");
				DKIM_FREE(dkim, hdrset);
				return DKIM_STAT_INTERNAL;
			}
		}

		/* canonicalize each marked header */
		for (c = 0; c < nhdrs; c++)
		{
			if (hdrset[c] != NULL &&
			    (hdrset[c]->hdr_flags & DKIM_HDR_SIGNED) != 0)
			{
				status = dkim_canon_header(dkim, cur,
				                           hdrset[c], TRUE);
				if (status != DKIM_STAT_OK)
				{
					DKIM_FREE(dkim, hdrset);
					return status;
				}
			}
		}

		/* if signing, we can't do the rest of this yet */
		if (signing)
			continue;

		/*
		**  We need to copy the DKIM-Signature: header being verified,
		**  minus the contents of the "b=" part, and include it in the
		**  canonicalization.  However, skip this if no hashing was
		**  done.
		*/

		dkim_dstring_blank(dkim->dkim_hdrbuf);

		tmp = tmpbuf;

		n = 0;
		in = '\0';
		for (p = cur->canon_sigheader->hdr_text; *p != '\0'; p++)
		{
			if (*p == ';')
				in = '\0';

			if (in == 'b')
			{
				last = *p;
				continue;
			}

			if (in == '\0' && *p == '=')
				in = last;

			*tmp++ = *p;

			/* flush buffer? */
			if (tmp == end)
			{
				*tmp = '\0';

				if (!dkim_dstring_catn(dkim->dkim_hdrbuf,
				                       tmpbuf, tmp - tmpbuf))
				{
					DKIM_FREE(dkim, hdrset);

					return DKIM_STAT_NORESOURCE;
				}

				tmp = tmpbuf;
			}

			last = *p;
		}

		/* flush anything cached */
		if (tmp != tmpbuf)
		{
			*tmp = '\0';

			if (!dkim_dstring_catn(dkim->dkim_hdrbuf,
			                       tmpbuf, tmp - tmpbuf))
			{
				DKIM_FREE(dkim, hdrset);

				return DKIM_STAT_NORESOURCE;
			}
		}

		/* canonicalize */
		tmphdr.hdr_text = dkim_dstring_get(dkim->dkim_hdrbuf);
		tmphdr.hdr_namelen = cur->canon_sigheader->hdr_namelen;
		tmphdr.hdr_colon = tmphdr.hdr_text + (cur->canon_sigheader->hdr_colon - cur->canon_sigheader->hdr_text);
		tmphdr.hdr_textlen = dkim_dstring_len(dkim->dkim_hdrbuf);
		tmphdr.hdr_flags = 0;
		tmphdr.hdr_next = NULL;

		if (cur->canon_canon == DKIM_CANON_RELAXED)
			dkim_lowerhdr(tmphdr.hdr_text);
		(void) dkim_canon_header(dkim, cur, &tmphdr, FALSE);
		dkim_canon_buffer(cur, NULL, 0);

		/* finalize */
		switch (cur->canon_hashtype)
		{
		  case DKIM_HASHTYPE_SHA1:
		  {
			struct dkim_sha1 *sha1;

			sha1 = (struct dkim_sha1 *) cur->canon_hash;
			SHA1_Final(sha1->sha1_out, &sha1->sha1_ctx);

			if (sha1->sha1_tmpbio != NULL)
				BIO_flush(sha1->sha1_tmpbio);

			break;
		  }

#ifdef DKIM_HASHTYPE_SHA256
		  case DKIM_HASHTYPE_SHA256:
		  {
			struct dkim_sha256 *sha256;

			sha256 = (struct dkim_sha256 *) cur->canon_hash;
			SHA256_Final(sha256->sha256_out, &sha256->sha256_ctx);

			if (sha256->sha256_tmpbio != NULL)
				BIO_flush(sha256->sha256_tmpbio);

			break;
		  }
#endif /* DKIM_HASHTYPE_SHA256 */

		  default:
			assert(0);
			/* NOTREACHED */
		}

		cur->canon_done = TRUE;
	}

	DKIM_FREE(dkim, hdrset);

	return DKIM_STAT_OK;
}

/*
**  DKIM_CANON_SIGNATURE -- append a signature header when signing
**
**  Parameters:
**  	dkim -- DKIM handle
**  	hdr -- header
**
**  Return value:
**  	A DKIM_STAT_* constant.
**
**  Notes:
**  	Header canonicalizations are finalized by this function.
*/

DKIM_STAT
dkim_canon_signature(DKIM *dkim, struct dkim_header *hdr)
{
	DKIM_STAT status;
	DKIM_CANON *cur;
	struct dkim_header tmphdr;

	assert(dkim != NULL);
	assert(hdr != NULL);

	if (dkim->dkim_hdrbuf == NULL)
	{
		dkim->dkim_hdrbuf = dkim_dstring_new(dkim, DKIM_MAXHEADER, 0);
		if (dkim->dkim_hdrbuf == NULL)
			return DKIM_STAT_NORESOURCE;
	}
	else
	{
		dkim_dstring_blank(dkim->dkim_hdrbuf);
	}

	for (cur = dkim->dkim_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done || !cur->canon_hdr)
			continue;

		/* prepare the data */
		dkim_dstring_copy(dkim->dkim_hdrbuf, hdr->hdr_text);
		tmphdr.hdr_text = dkim_dstring_get(dkim->dkim_hdrbuf);
		tmphdr.hdr_namelen = hdr->hdr_namelen;
		tmphdr.hdr_colon = tmphdr.hdr_text + (hdr->hdr_colon - hdr->hdr_text);
		tmphdr.hdr_textlen = dkim_dstring_len(dkim->dkim_hdrbuf);
		tmphdr.hdr_flags = 0;
		tmphdr.hdr_next = NULL;
		if (cur->canon_canon == DKIM_CANON_RELAXED)
			dkim_lowerhdr(tmphdr.hdr_text);
		
		/* canonicalize the signature */
		status = dkim_canon_header(dkim, cur, &tmphdr, FALSE);
		if (status != DKIM_STAT_OK)
			return status;
		dkim_canon_buffer(cur, NULL, 0);

		/* now close it */
		switch (cur->canon_hashtype)
		{
		  case DKIM_HASHTYPE_SHA1:
		  {
			struct dkim_sha1 *sha1;

			sha1 = (struct dkim_sha1 *) cur->canon_hash;
			SHA1_Final(sha1->sha1_out, &sha1->sha1_ctx);

			if (sha1->sha1_tmpbio != NULL)
				BIO_flush(sha1->sha1_tmpbio);

			break;
		  }

#ifdef DKIM_HASHTYPE_SHA256
		  case DKIM_HASHTYPE_SHA256:
		  {
			struct dkim_sha256 *sha256;

			sha256 = (struct dkim_sha256 *) cur->canon_hash;
			SHA256_Final(sha256->sha256_out, &sha256->sha256_ctx);

			if (sha256->sha256_tmpbio != NULL)
				BIO_flush(sha256->sha256_tmpbio);

			break;
		  }
#endif /* DKIM_HASHTYPE_SHA256 */

		  default:
			assert(0);
			/* NOTREACHED */
		}

		cur->canon_done = TRUE;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_CANON_MINBODY -- return number of bytes required to satisfy all
**                        canonicalizations
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	0 -- all canonicalizations satisfied
**  	ULONG_MAX -- at least one canonicalization wants the whole message
**  	other -- bytes required to satisfy all canonicalizations
*/

u_long
dkim_canon_minbody(DKIM *dkim)
{
	u_long minbody = 0;
	DKIM_CANON *cur;

	assert(dkim != NULL);

	for (cur = dkim->dkim_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done || cur->canon_hdr)
			continue;

		/* if this one wants the whole message, short-circuit */
		if (cur->canon_remain == (off_t) -1)
			return ULONG_MAX;

		/* compare to current minimum */
		minbody = MAX(minbody, (u_long) cur->canon_remain);
	}

	return minbody;
}

/*
**  DKIM_CANON_BODYCHUNK -- run a body chunk through all body
**                          canonicalizations
**
**  Parameters:
**  	dkim -- DKIM handle
**  	buf -- pointer to bytes to canonicalize
**  	buflen -- number of bytes to canonicalize
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_canon_bodychunk(DKIM *dkim, u_char *buf, size_t buflen)
{
	bool fixcrlf;
	DKIM_STAT status;
	u_int wlen;
	DKIM_CANON *cur;
	size_t plen;
	u_char *p;
	u_char *wrote;
	u_char *eob;
	u_char *start;

	assert(dkim != NULL);

	dkim->dkim_bodylen += buflen;

	fixcrlf = (dkim->dkim_libhandle->dkiml_flags & DKIM_LIBFLAGS_FIXCRLF) != 0 &&
	          (dkim->dkim_mode == DKIM_MODE_SIGN);

	for (cur = dkim->dkim_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done || cur->canon_hdr)
			continue;

		/* short-circuit completed canonicalizations */
		if (cur->canon_remain == 0)
			continue;

		start = buf;
		plen = buflen;

		if (fixcrlf)
		{
			status = dkim_canon_fixcrlf(dkim, cur, buf, buflen);
			if (status != DKIM_STAT_OK)
				return status;

			start = dkim_dstring_get(dkim->dkim_canonbuf);
			plen = dkim_dstring_len(dkim->dkim_canonbuf);
		}

		eob = start + plen - 1;
		wrote = start;
		wlen = 0;

		switch (cur->canon_canon)
		{
		  case DKIM_CANON_SIMPLE:
			for (p = start; p <= eob; p++)
			{
				if (*p == '\n')
				{
					if (cur->canon_lastchar == '\r')
					{
						if (cur->canon_blankline)
						{
							cur->canon_blanks++;
						}
						else if (wlen == 1)
						{
							dkim_canon_buffer(cur,
							                  CRLF,
							                  2);
						}
						else
						{
							dkim_canon_buffer(cur,
							                  wrote,
							                  wlen + 1);
						}

						wrote = p + 1;
						wlen = 0;
						cur->canon_blankline = TRUE;
					}
				}
				else
				{
					if (p == start && fixcrlf &&
					    cur->canon_lastchar == '\r')
					{
						dkim_canon_buffer(cur,
						                  "\n", 1);
						cur->canon_lastchar = '\n';
						cur->canon_blankline = TRUE;
					}

					if (*p != '\r')
					{
						if (cur->canon_blanks > 0)
							dkim_canon_flushblanks(cur);
						cur->canon_blankline = FALSE;
					}
					wlen++;
				}

				cur->canon_lastchar = *p;
			}

			break;

		  case DKIM_CANON_RELAXED:
			for (p = start; p <= eob; p++)
			{
				if (*p == '\n')
				{
					if (cur->canon_lastchar == '\r')
					{
						if (cur->canon_blankline)
						{
							cur->canon_blanks++;
						}
						else if (wlen == 1)
						{
							dkim_canon_buffer(cur,
							                  CRLF,
							                  2);
						}
						else
						{
							dkim_canon_buffer(cur,
							                  wrote,
							                  wlen + 1);
						}

						wrote = p + 1;
						wlen = 0;
						cur->canon_blankline = TRUE;
					}
				}
				else
				{
					if (p == start && fixcrlf &&
					    cur->canon_lastchar == '\r')
					{
						dkim_canon_buffer(cur,
						                  "\n", 1);
						cur->canon_lastchar = '\n';
						cur->canon_blankline = TRUE;
					}

					/* non-space after a space */
					if (DKIM_ISLWSP(cur->canon_lastchar) &&
					    !DKIM_ISLWSP(*p) && *p != '\r')
					{
						if (cur->canon_blanks > 0)
							dkim_canon_flushblanks(cur);
						dkim_canon_buffer(cur, SP, 1);
						wrote = p;
						wlen = 1;
						cur->canon_blankline = FALSE;
					}

					/* space after a non-space */
					else if (!DKIM_ISLWSP(cur->canon_lastchar) &&
					         DKIM_ISLWSP(*p))
					{
						if (cur->canon_blanks > 0)
							dkim_canon_flushblanks(cur);
						dkim_canon_buffer(cur, wrote,
							          wlen);
						wlen = 0;
						wrote = p + 1;
					}

					/* space after a space */
					else if (DKIM_ISLWSP(cur->canon_lastchar) &&
					         DKIM_ISLWSP(*p))
					{
						/* XXX -- fix logic */
						;
					}

					/* non-space after a non-space */
					else
					{
						wlen++;
						if (cur->canon_blankline &&
						    (wlen > 1 || *p != '\r'))
						{
							if (cur->canon_blanks > 0)
								dkim_canon_flushblanks(cur);
							cur->canon_blankline = FALSE;
						}
					}
				}

				cur->canon_lastchar = *p;
			}

			break;

		  default:
			assert(0);
			/* NOTREACHED */
		}

		dkim_canon_buffer(cur, wrote, wlen);
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_CANON_CLOSEBODY -- close all body canonicalizations
**
**  Parameters:
**  	dkim -- DKIM handle
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_canon_closebody(DKIM *dkim)
{
	DKIM_CANON *cur;

	assert(dkim != NULL);

	for (cur = dkim->dkim_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes or header canonicalizations */
		if (cur->canon_done || cur->canon_hdr)
			continue;

		/* "simple" canonicalization must include at least a CRLF */
		if (cur->canon_canon == DKIM_CANON_SIMPLE &&
		    cur->canon_wrote == 0)
			dkim_canon_buffer(cur, CRLF, 2);

		dkim_canon_buffer(cur, NULL, 0);

		/* finalize */
		switch (cur->canon_hashtype)
		{
		  case DKIM_HASHTYPE_SHA1:
		  {
			struct dkim_sha1 *sha1;

			sha1 = (struct dkim_sha1 *) cur->canon_hash;
			SHA1_Final(sha1->sha1_out, &sha1->sha1_ctx);

			if (sha1->sha1_tmpbio != NULL)
				BIO_flush(sha1->sha1_tmpbio);

			break;
		  }

#ifdef DKIM_HASHTYPE_SHA256
		  case DKIM_HASHTYPE_SHA256:
		  {
			struct dkim_sha256 *sha256;

			sha256 = (struct dkim_sha256 *) cur->canon_hash;
			SHA256_Final(sha256->sha256_out, &sha256->sha256_ctx);

			if (sha256->sha256_tmpbio != NULL)
				BIO_flush(sha256->sha256_tmpbio);

			break;
		  }
#endif /* DKIM_HASHTYPE_SHA256 */

		  default:
			assert(0);
			/* NOTREACHED */
		}

		cur->canon_done = TRUE;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIM_CANON_GETFINAL -- retrieve final digest
**
**  Parameters:
**  	canon -- DKIM_CANON handle
**  	digest -- pointer to the digest (returned)
**  	dlen -- digest length (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_canon_getfinal(DKIM_CANON *canon, u_char **digest, size_t *dlen)
{
	assert(canon != NULL);
	assert(digest != NULL);
	assert(dlen != NULL);

	if (!canon->canon_done)
		return DKIM_STAT_INVALID;

	switch (canon->canon_hashtype)
	{
	  case DKIM_HASHTYPE_SHA1:
	  {
		struct dkim_sha1 *sha1;

		sha1 = (struct dkim_sha1 *) canon->canon_hash;
		*digest = sha1->sha1_out;
		*dlen = sizeof sha1->sha1_out;

		return DKIM_STAT_OK;
	  }

#ifdef DKIM_HASHTYPE_SHA256
	  case DKIM_HASHTYPE_SHA256:
	  {
		struct dkim_sha256 *sha256;

		sha256 = (struct dkim_sha256 *) canon->canon_hash;
		*digest = sha256->sha256_out;
		*dlen = sizeof sha256->sha256_out;

		return DKIM_STAT_OK;
	  }
#endif /* DKIM_HASHTYPE_SHA256 */

	  default:
		assert(0);
		/* NOTREACHED */
		return DKIM_STAT_INTERNAL;
	}
}
