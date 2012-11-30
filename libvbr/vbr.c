/*
**  Copyright (c) 2007, 2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
*/

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! REENTRANT */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <resolv.h>

#ifdef __STDC__
# include <stdarg.h>
#else /* __STDC__ */
# include <varargs.h>
#endif /* _STDC_ */

/* libvbr includes */
#include "vbr.h"

#ifndef FALSE
# define FALSE			0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE			1
#endif /* ! TRUE */

#define BUFRSZ			2048
#define	DEFERRLEN		64
#define	DEFTIMEOUT		10
#define MAXCNAMEDEPTH		3

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */
#ifndef T_RRSIG
# define T_RRSIG		46
#endif /* ! T_RRSIG */

#define VBR_DNS_ERROR		(-1)
#define VBR_DNS_SUCCESS		0
#define VBR_DNS_REPLY		1
#define VBR_DNS_NOREPLY		2
#define VBR_DNS_EXPIRED		3

/* struct vbr_query -- an open VBR query */
struct vbr_query
{
	int		vq_error;
	size_t		vq_buflen;
	void *		vq_qh;
	u_char		vq_buf[HFIXEDSZ + MAXPACKET];
};

struct vbr_handle
{
	u_int		vbr_opts;		/* options */
	size_t		vbr_errlen;		/* error buffer size */
	u_int		vbr_timeout;		/* query timeout */
	u_int		vbr_callback_int;	/* callback interval */
	void *		vbr_user_context;	/* user context for callback */
	void		(*vbr_dns_callback) (const void *);
	void *		(*vbr_malloc) (void *, size_t);
	void		(*vbr_free) (void *, void *);
	void *		vbr_closure;		/* memory closure */
	u_char *	vbr_domain;		/* sending domain */
	u_char *	vbr_type;		/* message type */
	u_char *	vbr_cert;		/* claimed certifiers */
	u_char *	vbr_error;		/* error buffer */
	u_char **	vbr_trusted;		/* trusted certifiers */
	void		*vbr_dns_service;
	int		(*vbr_dns_start) (void *, int,
			                  unsigned char *,
			                  unsigned char *,
			                  size_t,
			                  void **);
	int		(*vbr_dns_cancel) (void *, void *);
	int		(*vbr_dns_init) (void **);
	void		(*vbr_dns_close) (void *);
	int		(*vbr_dns_setns) (void *, const char *);
	int		(*vbr_dns_config) (void *, const char *);
	int		(*vbr_dns_trustanchor) (void *, const char *);
	int		(*vbr_dns_waitreply) (void *,
			                      void *,
			                      struct timeval *,
			                      size_t *,
			                      int *,
			                      int *);
};

/* prototypes */
static void vbr_error __P((VBR *, const char *, ...));

/* ========================= PRIVATE SECTION ========================= */

#if USE_STRL_HCPY == 0

/*
**  Copyright (c) 1999-2002, Sendmail Inc. and its suppliers.
**	All rights reserved.
** 
**  By using this file, you agree to the terms and conditions set
**  forth in the LICENSE file which can be found at the top level of
**  the sendmail distribution.
**
**  Copyright (c) 2009, The Trusted Domain Project.  All rights reserved.
*/

/*
**  XXX the type of the length parameter has been changed
**  from size_t to ssize_t to avoid theoretical problems with negative
**  numbers passed into these functions.
**  The real solution to this problem is to make sure that this doesn't
**  happen, but for now we'll use this workaround.
*/

#define	strlcpy(x,y,z)	vbr_strlcpy((x), (y), (z))

/*
**  VBR_STRLCPY -- size bounded string copy
**
**	This is a bounds-checking variant of strcpy.
**	If size > 0, copy up to size-1 characters from the nul terminated
**	string src to dst, nul terminating the result.  If size == 0,
**	the dst buffer is not modified.
**	Additional note: this function has been "tuned" to run fast and tested
**	as such (versus versions in some OS's libc).
**
**	The result is strlen(src).  You can detect truncation (not all
**	of the characters in the source string were copied) using the
**	following idiom:
**
**		char *s, buf[BUFSIZ];
**		...
**		if (vbr_strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
**			goto overflow;
**
**	Parameters:
**		dst -- destination buffer
**		src -- source string
**		size -- size of destination buffer
**
**	Returns:
**		strlen(src)
*/

size_t
vbr_strlcpy(dst, src, size)
	register char *dst;
	register const char *src;
	ssize_t size;
{
	register ssize_t i;

	if (size-- <= 0)
		return strlen(src);
	for (i = 0; i < size && (dst[i] = src[i]) != 0; i++)
		continue;
	dst[i] = '\0';
	if (src[i] == '\0')
		return i;
	else
		return i + strlen(src + i);
}
#endif /* USE_STRL_HCPY == 0 */

/*
**  VBR_MALLOC -- allocate memory
**
**  Parameters:
**  	vbr -- VBR context in which this is performed
**  	closure -- opaque closure handle for the allocation
**  	nbytes -- number of bytes desired
**
**  Return value:
**  	Pointer to allocated memory, or NULL on failure.
*/

static void *
vbr_malloc(VBR *vbr, void *closure, size_t nbytes)
{
	assert(vbr != NULL);

	if (vbr->vbr_malloc == NULL)
		return malloc(nbytes);
	else
		return vbr->vbr_malloc(closure, nbytes);
}

/*
**  VBR_FREE -- release memory
**
**  Parameters:
**  	vbr -- VBR context in which this is performed
**  	closure -- opaque closure handle for the allocation
**  	ptr -- pointer to memory to be freed
**
**  Return value:
**  	None.
*/

static void
vbr_free(VBR *vbr, void *closure, void *ptr)
{
	assert(vbr != NULL);

	if (vbr->vbr_free == NULL)
		free(ptr);
	else
		vbr->vbr_free(closure, ptr);
}

/*
**  VBR_VERROR -- log an error into a VBR handle (varargs version)
**
**  Parameters:
**  	vbr -- VBR context in which this is performed
**  	format -- format to apply
**  	va -- argument list
**
**  Return value:
**  	None.
*/

static void
vbr_verror(VBR *vbr, const char *format, va_list va)
{
	int flen;
	int saverr;
	u_char *new;

	assert(vbr != NULL);
	assert(format != NULL);

	saverr = errno;

	if (vbr->vbr_error == NULL)
	{
		vbr->vbr_error = vbr_malloc(vbr, vbr->vbr_closure, DEFERRLEN);
		if (vbr->vbr_error == NULL)
		{
			errno = saverr;
			return;
		}
		vbr->vbr_errlen = DEFERRLEN;
	}

	for (;;)
	{
		flen = vsnprintf((char *) vbr->vbr_error, vbr->vbr_errlen,
		                 format, va);

		/* compensate for broken vsnprintf() implementations */
		if (flen == -1)
			flen = vbr->vbr_errlen * 2;

		if (flen >= vbr->vbr_errlen)
		{
			new = vbr_malloc(vbr, vbr->vbr_closure, flen + 1);
			if (new == NULL)
			{
				errno = saverr;
				return;
			}

			vbr_free(vbr, vbr->vbr_closure, vbr->vbr_error);
			vbr->vbr_error = new;
			vbr->vbr_errlen = flen + 1;
		}
		else
		{
			break;
		}
	}

	errno = saverr;
}

/*
**  VBR_ERROR -- log an error into a VBR handle
**
**  Parameters:
**  	vbr -- VBR context in which this is performed
**  	format -- format to apply
**  	... -- arguments
**
**  Return value:
**  	None.
*/

static void
vbr_error(VBR *vbr, const char *format, ...)
{
	va_list va;

	assert(vbr != NULL);
	assert(format != NULL);

	va_start(va, format);
	vbr_verror(vbr, format, va);
	va_end(va);
}

/*
**  VBR_TIMEOUTS -- do timeout math
**
**  Parameters:
**  	timeout -- general VBR timeout
**  	ctimeout -- callback timeout
**  	wstart -- previous wait start time
** 	wstop -- previous wait stop time
**  	next -- computed next timeout (updated)
**
**  Return value:
**  	None.
*/

static void
vbr_timeouts(struct timeval *timeout, struct timeval *ctimeout,
             struct timeval *wstart, struct timeval *wstop,
             struct timeval **next)
{
	assert(timeout != NULL);
	assert(ctimeout != NULL);
	assert(wstart != NULL);
	assert(wstop != NULL);
	assert(next != NULL);

	if (wstop->tv_sec == 0 && wstop->tv_usec == 0)
	{
		/* first pass */
		if (timeout->tv_sec < ctimeout->tv_sec ||
		    (timeout->tv_sec == ctimeout->tv_sec &&
		     timeout->tv_usec < ctimeout->tv_usec))
			*next = timeout;
		else
			*next = ctimeout;
	}
	else
	{
		struct timeval to1;
		struct timeval to2;

		/* compute start through overall timeout */
		memcpy(&to1, wstart, sizeof to1);
		to1.tv_sec += timeout->tv_sec;
		to1.tv_usec += timeout->tv_usec;
		if (to1.tv_usec > 1000000)
		{
			to1.tv_sec += (to1.tv_usec / 1000000);
			to1.tv_usec = (to1.tv_usec % 1000000);
		}

		/* compute stop through callback timeout */
		memcpy(&to2, wstop, sizeof to2);
		to2.tv_sec += ctimeout->tv_sec;
		to2.tv_usec += ctimeout->tv_usec;
		if (to2.tv_usec > 1000000)
		{
			to2.tv_sec += (to2.tv_usec / 1000000);
			to2.tv_usec = (to2.tv_usec % 1000000);
		}

		/* ...and decide */
		if (to1.tv_sec < to2.tv_sec ||
		    (to1.tv_sec == to2.tv_sec &&
		     to1.tv_usec < to2.tv_usec))
			*next = timeout;
		else
			*next = ctimeout;
	}
}

/*
**  VBR_RES_CANCEL -- cancel a pending resolver query
**
**  Parameters:
**  	srv -- query service handle (ignored)
**  	qh -- query handle (ignored)
**
**  Return value:
**  	0 on success, !0 on error
**
**  Notes:
**  	The standard UNIX resolver is synchronous, so in theory this can
**  	never get called.  We have not yet got any use cases for one thread
**  	canceling another thread's pending queries, so for now just return 0.
*/

static int
vbr_res_cancel(void *srv, void *qh)
{
	if (qh != NULL)
		free(qh);

	return 0;
}

/*
**  VBR_RES_QUERY -- initiate a DNS query
**
**  Parameters:
**  	srv -- service handle (ignored)
**  	type -- RR type to query
**  	query -- the question to ask
**  	buf -- where to write the answer
**  	buflen -- bytes at "buf"
** 	qh -- query handle, used with vbr_res_waitreply
**
**  Return value:
**  	An VBR_DNS_* constant.
**
**  Notes:
**  	This is a stub for the stock UNIX resolver (res_) functions, which
**  	are synchronous so no handle needs to be created, so "qh" is set to
**  	"buf".  "buf" is actually populated before this returns (unless
**  	there's an error).
*/

static int
vbr_res_query(void *srv, int type, unsigned char *query, unsigned char *buf,
              size_t buflen, void **qh)
{
	int n;
	int ret;
	struct vbr_query *vq;
	unsigned char qbuf[HFIXEDSZ + MAXPACKET];
#ifdef HAVE_RES_NINIT
	struct __res_state statp;
#endif /* HAVE_RES_NINIT */

#ifdef HAVE_RES_NINIT
	memset(&statp, '\0', sizeof statp);
	res_ninit(&statp);
#endif /* HAVE_RES_NINIT */

#ifdef HAVE_RES_NINIT
	n = res_nmkquery(&statp, QUERY, (char *) query, C_IN, type, NULL, 0,
	                 NULL, qbuf, sizeof qbuf);
#else /* HAVE_RES_NINIT */
	n = res_mkquery(QUERY, (char *) query, C_IN, type, NULL, 0, NULL, qbuf,
	                sizeof qbuf);
#endif /* HAVE_RES_NINIT */
	if (n == (size_t) -1)
	{
#ifdef HAVE_RES_NINIT
		res_nclose(&statp);
#endif /* HAVE_RES_NINIT */
		return VBR_DNS_ERROR;
	}

#ifdef HAVE_RES_NINIT
	ret = res_nsend(&statp, qbuf, n, buf, buflen);
#else /* HAVE_RES_NINIT */
	ret = res_send(qbuf, n, buf, buflen);
#endif /* HAVE_RES_NINIT */
	if (ret == -1)
	{
#ifdef HAVE_RES_NINIT
		res_nclose(&statp);
#endif /* HAVE_RES_NINIT */
		return VBR_DNS_ERROR;
	}

#ifdef HAVE_RES_NINIT
	res_nclose(&statp);
#endif /* HAVE_RES_NINIT */

	vq = (struct vbr_query *) malloc(sizeof *vq);
	if (vq == NULL)
		return VBR_DNS_ERROR;

	if (ret == -1)
	{
		vq->vq_error = errno;
		vq->vq_buflen = 0;
	}
	else
	{
		vq->vq_error = 0;
		vq->vq_buflen = (size_t) ret;
	}

	*qh = (void *) vq;

	return VBR_DNS_SUCCESS;
}

/*
**  VBR_RES_WAITREPLY -- wait for a reply to a pending query
**
**  Parameters:
**  	srv -- service handle
**  	qh -- query handle
**  	to -- timeout
**  	bytes -- number of bytes in the reply (returned)
**  	error -- error code (returned)
**
**  Return value:
**  	A VBR_DNS_* code.
**
**  Notes:
**  	Since the stock UNIX resolver is synchronous, the reply was completed
** 	before vbr_res_query() returned, and thus this is almost a no-op.
*/

int
vbr_res_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                  int *error, int *dnssec)
{
	struct vbr_query *vq;

	assert(qh != NULL);

	vq = qh;

	if (bytes != NULL)
		*bytes = vq->vq_buflen;
	if (error != NULL)
		*error = vq->vq_error;

	return VBR_DNS_SUCCESS;
}

/*
**  VBR_TXT_DECODE -- decode a TXT reply
**
**  Parameters:
**  	ansbuf -- answer buffer
**  	anslen -- size of answer buffer
**  	buf -- output buffer
**  	buflen -- size of output buffer
**
**  Return value:
**  	TRUE iff ansbuf contains an IN TXT reply that could be deocde.
*/

static _Bool
vbr_txt_decode(u_char *ansbuf, size_t anslen, u_char *buf, size_t buflen)
{
	int type = -1;
	int class = -1;
	int qdcount;
	int ancount;
	int n;
	int c;
	u_char *cp;
	u_char *eom;
	u_char *p;
	HEADER hdr;
	char qname[VBR_MAXHOSTNAMELEN + 1];

	assert(ansbuf != NULL);
	assert(buf != NULL);

	/* set up pointers */
	memcpy(&hdr, ansbuf, sizeof hdr);
	cp = ansbuf + HFIXEDSZ;
	eom = ansbuf + anslen;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		(void) dn_expand(ansbuf, eom, cp, qname, sizeof qname);

		if ((n = dn_skipname(cp, eom)) < 0)
			return FALSE;
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
			return FALSE;

		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != T_TXT || class != C_IN)
		return FALSE;

	if (hdr.rcode == NXDOMAIN)
		return FALSE;

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return FALSE;

	/* if truncated, we can't do it */
	if (hdr.tc)
		return FALSE;

	/* grab the label, even though we know what we asked... */
	if ((n = dn_expand(ansbuf, eom, cp, (RES_UNC_T) qname,
	                   sizeof qname)) < 0)
		return FALSE;
	/* ...and move past it */
	cp += n;

	/* extract the type and class */
	if (cp + INT16SZ + INT16SZ > eom)
		return FALSE;
	GETSHORT(type, cp);
	GETSHORT(class, cp);

	/* reject anything that's not valid (stupid wildcards) */
	if (type != T_TXT || class != C_IN)
		return FALSE;

	/* skip the TTL */
	cp += INT32SZ;

	/* get payload length */
	if (cp + INT16SZ > eom)
		return FALSE;
	GETSHORT(n, cp);

	/* XXX -- maybe deal with a partial reply rather than require it all */
	if (cp + n > eom)
		return FALSE;

	if (n > buflen)
		return FALSE;

	/* extract the payload */
	memset(buf, '\0', buflen);
	p = buf;
	while (n > 0)
	{
		c = *cp++;
		n--;
		while (c > 0)
		{
			*p++ = *cp++;
			c--;
			n--;
		}
	}

	return TRUE;
}

/* ========================= PUBLIC SECTION ========================= */

/*
**  VBR_INIT -- initialize a VBR handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new VBR handle suitable for use with other VBR functions, or
**  	NULL on failure.
**  
**  Side effects:
**  	Strange radar returns at Indianapolis ARTCC.
*/

VBR *
vbr_init(void *(*caller_mallocf)(void *closure, size_t nbytes),
         void (*caller_freef)(void *closure, void *p),
         void *closure)
{
	VBR *new;

	/* copy the parameters */
	new = (VBR *) malloc(sizeof(struct vbr_handle));
	if (new == NULL)
		return NULL;

	new->vbr_malloc = caller_mallocf;
	new->vbr_free = caller_freef;
	new->vbr_closure = closure;
	new->vbr_timeout = DEFTIMEOUT;
	new->vbr_callback_int = 0;
	new->vbr_dns_callback = NULL;
	new->vbr_user_context = NULL;
	new->vbr_errlen = 0;
	new->vbr_error = NULL;

	new->vbr_domain = NULL;
	new->vbr_type = NULL;
	new->vbr_cert = NULL;
	new->vbr_trusted = NULL;

	new->vbr_dns_service = NULL;
	new->vbr_dns_start = vbr_res_query;
	new->vbr_dns_waitreply = vbr_res_waitreply;
	new->vbr_dns_cancel = vbr_res_cancel;
	new->vbr_dns_init = NULL;
	new->vbr_dns_close = NULL;
	new->vbr_dns_setns = NULL;
	new->vbr_dns_config = NULL;
	new->vbr_dns_trustanchor = NULL;

	return new;
}

/*
**  VBR_OPTIONS -- set VBR options
**
**  Parameters:
**  	vbr -- VBR handle to modify
**  	opts -- bitmask of options to use
**
**  Return value:
**  	None.
*/

void
vbr_options(VBR *vbr, unsigned int opts)
{
	assert(vbr != NULL);

	vbr->vbr_opts = opts;
}

#define	CLOBBER(x)	if ((x) != NULL) \
			{ \
				vbr_free(vbr, vbr->vbr_closure, (x)); \
				(x) = NULL; \
			}

/*
**  VBR_CLOSE -- shut down a VBR instance
**
**  Parameters:
**  	vbr -- VBR handle to shut down
**
**  Return value:
**  	None.
*/

void
vbr_close(VBR *vbr)
{
	assert(vbr != NULL);

	if (vbr->vbr_dns_close != NULL && vbr->vbr_dns_service != NULL)
		(void) vbr->vbr_dns_close(vbr->vbr_dns_service);

	CLOBBER(vbr->vbr_error);

	CLOBBER(vbr);
}

/*
**  VBR_GETERROR -- return any stored error string from within the VBR
**                  context handle
**
**  Parameters:
**  	vbr -- VBR handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

const u_char *
vbr_geterror(VBR *vbr)
{
	assert(vbr != NULL);

	return vbr->vbr_error;
}

/* XXX -- need a function to take in a VBR-Info: header and parse it? */

/*
**  VBR_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

VBR_STAT
vbr_settimeout(VBR *vbr, u_int timeout)
{
	assert(vbr != NULL);

	vbr->vbr_timeout = timeout;
	return VBR_STAT_OK;
}

/*
**  VBR_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

VBR_STAT
vbr_setcallbackint(VBR *vbr, u_int cbint)
{
	assert(vbr != NULL);

	vbr->vbr_callback_int = cbint;
	return VBR_STAT_OK;
}

/*
**  VBR_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

VBR_STAT
vbr_setcallbackctx(VBR *vbr, void *ctx)
{
	assert(vbr != NULL);

	vbr->vbr_user_context = ctx;
	return VBR_STAT_OK;
}

/*
**  VBR_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

VBR_STAT
vbr_setdnscallback(VBR *vbr, void (*func)(const void *context))
{
	assert(vbr != NULL);

	vbr->vbr_dns_callback = func;
	return VBR_STAT_OK;
}

/*
**  VBR_SETDOMAIN -- declare the sender's domain
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	cert -- certifiers string
**
**  Return value:
**  	None (yet).
*/

void
vbr_setdomain(VBR *vbr, u_char *domain)
{
	assert(vbr != NULL);
	assert(domain != NULL);

	vbr->vbr_domain = domain;
}

/*
**  VBR_SETCERT -- store the VBR certifiers of this message
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	cert -- certifiers string
**
**  Return value:
**  	None (yet).
*/

void
vbr_setcert(VBR *vbr, u_char *cert)
{
	assert(vbr != NULL);
	assert(cert != NULL);

	vbr->vbr_cert = cert;
}

/*
**  VBR_SETTYPE -- store the VBR type of this message
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	type -- type string
**
**  Return value:
**  	None (yet).
*/

void
vbr_settype(VBR *vbr, u_char *type)
{
	assert(vbr != NULL);
	assert(type != NULL);

	vbr->vbr_type = type;
}

/*
**  VBR_TRUSTEDCERTS -- store the trusted VBR certifiers
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	certs -- NULL-terminated list of trusted certifiers
**
**  Return value:
**  	None (yet).
*/

void
vbr_trustedcerts(VBR *vbr, u_char **certs)
{
	assert(vbr != NULL);
	assert(certs != NULL);

	vbr->vbr_trusted = certs;
}

/*
**  VBR_QUERY -- query the vouching servers for results
**
**  Parameters:
**  	vbr -- VBR handle
**  	res -- result string (one of "fail", "pass"); returned
**  	cert -- name of the certifier that returned a "pass"; returned
**
**  Return value:
**  	VBR_STAT_OK -- able to determine a result
**  	VBR_STAT_INVALID -- vbr_trustedcerts(), vbr_settype() and
**  	                    vbr_setcert() were not all called
**  	VBR_STAT_DNSERROR -- DNS issue prevented resolution
**
**  Notes:
**  	- "pass" is the result if ANY certifier vouched for the message.
**  	- "res" is not modified if no result could be determined
**  	- there's no attempt to validate the values found
**  	- vbr_cert is destroyed by this function
*/

VBR_STAT
vbr_query(VBR *vbr, u_char **res, u_char **cert)
{
	int c;
	int n;
	int status;
	int dnserr;
	struct vbr_query *vq;
	void *qh;
	u_char *p;
	u_char *last;
	u_char *last2;
	u_char *p2;
	struct timeval timeout;
	u_char certs[VBR_MAXHEADER + 1];
	u_char query[VBR_MAXHOSTNAMELEN + 1];
	unsigned char buf[BUFRSZ];

	assert(vbr != NULL);
	assert(res != NULL);
	assert(cert != NULL);

	if (vbr->vbr_type == NULL ||
	    vbr->vbr_cert == NULL ||
	    vbr->vbr_trusted == NULL)
	{
		vbr_error(vbr, "required data for VBR check missing");
		return VBR_STAT_INVALID;
	}

	strlcpy((char *) certs, vbr->vbr_cert, sizeof certs);

	if (vbr->vbr_malloc != NULL)
		vq = vbr->vbr_malloc(vbr->vbr_closure, sizeof(*vq));
	else
		vq = malloc(sizeof(*vq));

	if (vq == NULL)
		return VBR_STAT_NORESOURCE;

	memset(vq, '\0', sizeof *vq);

	for (c = 0; ; c++)
	{
		if ((vbr->vbr_opts & VBR_OPT_TRUSTEDONLY) != 0)
		{
			/*
			**  Query our trusted vouchers regardless of what the
			**  sender said.
			*/

			if (vbr->vbr_trusted[c] == NULL)
				break;
			else
				p = vbr->vbr_trusted[c];
		}
		else
		{
			/*
			**  Query the sender's vouchers that also appear in our
			**  trusted voucher list.
			*/

			_Bool found;

			p = (u_char *) strtok_r(c == 0 ? (char *) certs : NULL,
			                        ":", (char **) &last);
			if (p == NULL)
				break;

			found = FALSE;

			for (n = 0; vbr->vbr_trusted[n] != NULL; n++)
			{
				if (strcasecmp((char *) p,
				               (char *) vbr->vbr_trusted[n]) == 0)
				{
					found = TRUE;
					break;
				}
			}

			if (!found)
				continue;
		}	

		snprintf((char *) query, sizeof query, "%s.%s.%s",
		         vbr->vbr_domain, VBR_PREFIX, p);

		qh = NULL;

		if (vbr->vbr_dns_init != NULL &&
		    vbr->vbr_dns_service == NULL &&
		    vbr->vbr_dns_init(&vbr->vbr_dns_service) != 0)
		{
			snprintf(vbr->vbr_error, sizeof vbr->vbr_error,
			         "unable to start resolver for '%s'",
			         query);
			return VBR_STAT_DNSERROR;
		}

		status = vbr->vbr_dns_start(vbr->vbr_dns_service, T_TXT, query,
		                            vq->vq_buf, sizeof vq->vq_buf,
		                            &vq->vq_qh);

		if (status != VBR_STAT_OK)
		{
			snprintf(vbr->vbr_error, sizeof vbr->vbr_error,
			         "unable to start query for '%s'",
			         query);
			return VBR_STAT_DNSERROR;
		}

		timeout.tv_sec = vbr->vbr_timeout;
		timeout.tv_usec = 0;

		if (vbr->vbr_dns_callback == NULL)
		{
			status = vbr->vbr_dns_waitreply(vbr->vbr_dns_service,
			                                vq->vq_qh,
			                                &timeout,
			                                &vq->vq_buflen,
			                                &dnserr,
			                                NULL);
		}
		else
		{
			struct timeval *to;
			struct timeval wstart;
			struct timeval wstop;
			struct timeval ctimeout;

			wstop.tv_sec = 0;
			wstop.tv_usec = 0;

			for (;;)
			{
				(void) gettimeofday(&wstart, NULL);

				ctimeout.tv_sec = vbr->vbr_callback_int;
				ctimeout.tv_usec = 0;

				timeout.tv_sec = vbr->vbr_timeout;
				timeout.tv_usec = 0;

				vbr_timeouts(&timeout, &ctimeout,
				             &wstart, &wstop,
				             &to);

				status = vbr->vbr_dns_waitreply(vbr->vbr_dns_service,
				                                vq->vq_qh,
				                                to,
				                                &vq->vq_buflen,
				                                &dnserr,
				                                NULL);

				(void) gettimeofday(&wstop, NULL);

				if (status != VBR_DNS_NOREPLY ||
				    to == &timeout)
					break;

				vbr->vbr_dns_callback(vbr->vbr_user_context);
			}
		}

		vbr->vbr_dns_cancel(vbr->vbr_dns_service, vq->vq_qh);

		if (status == VBR_DNS_ERROR || status == VBR_DNS_EXPIRED)
		{
			vbr_error(vbr, "failed to retrieve %s", query);
			return VBR_STAT_DNSERROR;
		}

		/* try to decode the reply */
		if (!vbr_txt_decode(vq->vq_buf, vq->vq_buflen,
		                    buf, sizeof buf))
			continue;

		/* see if there's a vouch match */
		for (p2 = (u_char *) strtok_r((char *) buf, " \t",
		                              (char **) &last2);
		     p2 != NULL;
		     p2 = (u_char *) strtok_r(NULL, " \t",
		                              (char **) &last2))
		{
			if (strcasecmp((char *) p2, VBR_ALL) == 0 ||
			    strcasecmp((char *) p2,
			               (char *) vbr->vbr_type) == 0)
			{
				/* we have a winner! */
				*res = (u_char *) "pass";
				*cert = p;
				return VBR_STAT_OK;
			}
		}
	}

	/* nobody vouched */
	*res = (u_char *) "fail";
	return VBR_STAT_OK;
}

/*
**  VBR_GETHEADER -- generate and store the VBR-Info header
**
**  Parameters:
**  	vbr -- VBR handle
**  	hdr -- header buffer
**  	len -- number of bytes available at "hdr"
**
**  Return value:
**  	VBR_STAT_OK -- success
**  	VBR_STAT_NORESOURCE -- "hdr" was too short
**  	VBR_STAT_INVALID -- not all VBR information was provided
*/

VBR_STAT
vbr_getheader(VBR *vbr, unsigned char *hdr, size_t len)
{
	size_t olen;

	assert(vbr != NULL);
	assert(hdr != NULL);

	if (vbr->vbr_cert == NULL || vbr->vbr_type == NULL)
	{
		vbr_error(vbr, "VBR certifiers or type missing");
		return VBR_STAT_INVALID;
	}

	olen = snprintf((char *) hdr, len, "md=%s; mc=%s; mv=%s",
	                vbr->vbr_domain, vbr->vbr_type, vbr->vbr_cert);
	if (olen >= len)
	{
		vbr_error(vbr, "VBR buffer too small");
		return VBR_STAT_NORESOURCE;
	}

	return VBR_STAT_OK;
}

/*
**  VBR_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                               query service to be used, returning any
**                               previous handle
**
**  Parameters:
**  	vbr -- VBR library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

void *
vbr_dns_set_query_service(VBR *vbr, void *h)
{
	void *old;

	assert(vbr != NULL);

	old = vbr->vbr_dns_service;

	vbr->vbr_dns_service = h;

	return old;
}

/*
**  VBR_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             vbr_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

void
vbr_dns_set_query_start(VBR *vbr, int (*func)(void *, int,
                                              unsigned char *,
                                              unsigned char *,
                                              size_t, void **))
{
	assert(vbr != NULL);

	vbr->vbr_dns_start = func;
}

/*
**  VBR_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel function
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to cancel running queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- query handle to be canceled
*/

void
vbr_dns_set_query_cancel(VBR *vbr, int (*func)(void *, void *))
{
	assert(vbr != NULL);

	vbr->vbr_dns_cancel = func;
}

/*
**  VBR_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a DNS reply
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to wait for a reply
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- handle of query that has completed
**  		struct timeval *timeout -- how long to wait
**  		size_t *bytes -- bytes returned
**  		int *error -- error code returned
**  		int *dnssec -- DNSSEC status returned
*/

void
vbr_dns_set_query_waitreply(VBR *vbr, int (*func)(void *, void *,
                                                  struct timeval *,
                                                  size_t *, int *,
                                                  int *))
{
	assert(vbr != NULL);

	vbr->vbr_dns_waitreply = func;
}

/*
**  VBR_DNS_SET_INIT -- stores a pointer to a function that initializes
**                      a resolver
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to initialize a resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void **dns -- DNS service handle (returned)
*/

void
vbr_dns_set_init(VBR *vbr, int (*func)(void **))
{
	assert(vbr != NULL);

	vbr->vbr_dns_init = func;
}

/*
**  VBR_DNS_SET_CLOSE -- stores a pointer to a function that terminates
**                       a resolver
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to terminate a resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns void
**  		void *dns -- DNS service handle
*/

void
vbr_dns_set_close(VBR *vbr, void (*func)(void *))
{
	assert(vbr != NULL);

	vbr->vbr_dns_close = func;
}

/*
**  VBR_DNS_SET_NSLIST -- stores a pointer to a function that updates
**                        the active nameserver list
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to update the active nameserver list
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		const char *nslist -- nameserver list
*/

void
vbr_dns_set_nslist(VBR *vbr, int (*func)(void *, const char *))
{
	assert(vbr != NULL);

	vbr->vbr_dns_setns = func;
}

/*
**  VBR_DNS_SET_CONFIG -- stores a pointer to a function that provides
**                        resolver configuration
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to pass resolver configuration data
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		const char *config -- resolver configuration data
*/

void
vbr_dns_set_config(VBR *vbr, int (*func)(void *, const char *))
{
	assert(vbr != NULL);

	vbr->vbr_dns_config = func;
}

/*
**  VBR_DNS_SET_TRUSTANCHOR -- stores a pointer to a function that provides
**                             trust anchor data
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to pass trust anchor data
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		const char *trust -- trust anchor data
*/

void
vbr_dns_set_trustanchor(VBR *vbr, int (*func)(void *, const char *))
{
	assert(vbr != NULL);

	vbr->vbr_dns_trustanchor = func;
}

/*
**  VBR_DNS_NSLIST -- requests update to a nameserver list
**
**  Parameters:
**  	lib -- RBL library handle
**  	nslist -- comma-separated list of nameservers to use
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

VBR_STAT
vbr_dns_nslist(VBR *lib, const char *nslist)
{
	int status;

	assert(lib != NULL);
	assert(nslist != NULL);

	if (lib->vbr_dns_setns != NULL)
	{
		status = lib->vbr_dns_setns(lib->vbr_dns_service, nslist);
		if (status != 0)
			return VBR_STAT_DNSERROR;
	}

	return VBR_STAT_OK;
}

/*
**  VBR_DNS_CONFIG -- requests a change to resolver configuration
**
**  Parameters:
**  	lib -- RBL library handle
**  	config -- opaque configuration string
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

VBR_STAT
vbr_dns_config(VBR *lib, const char *config)
{
	int status;

	assert(lib != NULL);
	assert(config != NULL);

	if (lib->vbr_dns_config != NULL)
	{
		status = lib->vbr_dns_config(lib->vbr_dns_service, config);
		if (status != 0)
			return VBR_STAT_DNSERROR;
	}

	return VBR_STAT_OK;
}

/*
**  VBR_DNS_TRUSTANCHOR -- requests a change to resolver trust anchor data
**
**  Parameters:
**  	lib -- RBL library handle
**  	trust -- opaque trust anchor string
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

VBR_STAT
vbr_dns_trustanchor(VBR *lib, const char *trust)
{
	int status;

	assert(lib != NULL);
	assert(trust != NULL);

	if (lib->vbr_dns_trustanchor != NULL)
	{
		status = lib->vbr_dns_trustanchor(lib->vbr_dns_service, trust);
		if (status != 0)
			return VBR_STAT_DNSERROR;
	}

	return VBR_STAT_OK;
}

/*
**  VBR_DNS_INIT -- force nameserver (re)initialization
**
**  Parameters:
**  	lib -- RBL library handle
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

VBR_STAT
vbr_dns_init(VBR *lib)
{
	int status;

	assert(lib != NULL);

	if (lib->vbr_dns_service != NULL &&
	    lib->vbr_dns_close != NULL)
		lib->vbr_dns_close(lib->vbr_dns_service);

	lib->vbr_dns_service = NULL;

	if (lib->vbr_dns_init != NULL)
		return lib->vbr_dns_init(&lib->vbr_dns_service);
	else
		return VBR_STAT_OK;
}

