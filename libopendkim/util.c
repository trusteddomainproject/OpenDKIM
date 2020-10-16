/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2013, 2015, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>

/* libopendkim includes */
#include "dkim-internal.h"
#include "util.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

/*
**  DKIM_COLLAPSE -- remove spaces from a string
**
**  Parameters:
**  	str -- string to process
**
**  Return value:
**  	None.
*/

void
dkim_collapse(u_char *str)
{
	u_char *q;
	u_char *r;

	assert(str != NULL);

	for (q = str, r = str; *q != '\0'; q++)
	{
		if (!isspace(*q))
		{
			if (q != r)
				*r = *q;
			r++;
		}
	}

	*r = '\0';
}

/*
**  DKIM_HDRLIST -- build up a header list for use in a regexp
**
**  Parameters:
**  	buf -- where to write
**  	buflen -- bytes at "buf"
**  	hdrlist -- array of header names
**  	first -- first call
**
**  Return value:
**  	TRUE iff everything fit.
*/

_Bool
dkim_hdrlist(u_char *buf, size_t buflen, u_char **hdrlist, _Bool first)
{
	_Bool escape = FALSE;
	int c;
	int len;
	u_char *p;
	u_char *q;
	u_char *end;

	assert(buf != NULL);
	assert(hdrlist != NULL);

	for (c = 0; ; c++)
	{
		if (hdrlist[c] == NULL)
			break;

		if (!first)
		{
			len = strlcat((char *) buf, "|", buflen);
			if (len >= buflen)
				return FALSE;
		}
		else
		{
			len = strlen((char *) buf);
		}

		first = FALSE;

		q = &buf[len];
		end = &buf[buflen - 1];

		for (p = hdrlist[c]; *p != '\0'; p++)
		{
			if (q >= end)
				return FALSE;

			if (escape)
			{
				*q = *p;
				q++;
				escape = FALSE;
			}

			switch (*p)
			{
			  case '*':
				*q = '.';
				q++;
				if (q >= end)
					return FALSE;
				*q = '*';
				q++;
				break;

			  case '.':
				*q = '\\';
				q++;
				if (q >= end)
					return FALSE;
				*q = '.';
				q++;
				break;

			  case '\\':
				escape = TRUE;
				break;

			  default:
				*q = *p;
				q++;
				break;
			}
		}
	}

	return TRUE;
}

/*
**  DKIM_LOWERHDR -- convert a string (presumably a header) to all lowercase,
**                   but only up to a colon
**
**  Parameters:
**  	str -- string to modify
**
**  Return value:
**  	None.
*/

void
dkim_lowerhdr(unsigned char *str)
{
	unsigned char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (*p == ':')
			return;

		if (isascii(*p) && isupper(*p))
			*p = tolower(*p);
	}
}

/*
**  DKIM_HEXCHAR -- translate a hexadecimal character
**  
**  Parameters:
**  	c -- character to translate
**
**  Return value:
**  	Decimal equivalent.
*/

int
dkim_hexchar(int c)
{
	switch (c)
	{
	  case '0':
	  case '1':
	  case '2':
	  case '3':
	  case '4':
	  case '5':
	  case '6':
	  case '7':
	  case '8':
	  case '9':
		return c - '0';

	  case 'A':
	  case 'B':
	  case 'C':
	  case 'D':
	  case 'E':
	  case 'F':
		return 10 + c - 'A';

	  case 'a':
	  case 'b':
	  case 'c':
	  case 'd':
	  case 'e':
	  case 'f':
		return 10 + c - 'a';

	  default:
		assert(0);
		return -1;
	}
}

/*
**  DKIM_QP_ENCODE -- encode a string as quoted-printable
**
**  Parameters:
**  	in -- input
**  	out -- output
**  	outlen -- bytes available at "out"
**
**  Return value:
**  	>= 0 -- number of bytes in output
**  	-1 -- failure (not enough space)
**
**  Notes:
**  	The function does not guarantee string termination.
*/

int
dkim_qp_encode(unsigned char *in, unsigned char *out, int outlen)
{
	unsigned char const *p;
	unsigned char *q;
	unsigned char *end;
	size_t len;

	assert(in != NULL);
	assert(out != NULL);

	end = out + outlen;
	len = 0;

	for (p = in, q = out; *p != '\0'; p++)
	{
		if (q >= end)
			return -1;

		if ((*p >= 0x21 && *p <= 0x3a) ||
		    *p == 0x3c ||
		    (*p >= 0x3e && *p <= 0x7e))
		{
			*q = *p;
			q++;
			len++;
		}
		else if (q < end - 4)
		{
			snprintf((char *) q, 4,
				 "=%02X", *p);
			q += 3;
			len += 3;
		}
	}

	return len;
}

/*
**  DKIM_QP_DECODE -- decode a quoted-printable string
**
**  Parameters:
**  	in -- input
**  	out -- output
**  	outlen -- bytes available at "out"
**
**  Return value:
**  	>= 0 -- number of bytes in output
**  	-1 -- parse error
**
**  Notes:
**  	The returned number of bytes can be larger than "outlen" if
**  	"out" wasn't big enough to contain the decoded output.  The function
**  	does not guarantee string termination.
*/

int
dkim_qp_decode(unsigned char *in, unsigned char *out, int outlen)
{
	unsigned char next1;
	unsigned char next2 = 0;
	int xl;
	int decode = 0;
	unsigned char const *p;
	unsigned char *q;
	unsigned char *pos;
	unsigned char const *start;
	unsigned char const *stop;
	unsigned char *end;
	char const *hexdigits = "0123456789ABCDEF";

	assert(in != NULL);
	assert(out != NULL);

	start = NULL;
	stop = NULL;

	end = out + outlen;

	for (p = in, q = out; *p != '\0'; p++)
	{
		switch (*p)
		{
		  case '=':
			next1 = *(p + 1);
			if (next1 != '\0')
				next2 = *(p + 2);

			/* = at EOL */
			if (next1 == '\n' ||
			    (next1 == '\r' && next2 == '\n'))
			{
				stop = p;
				if (start != NULL)
				{
					unsigned char const *x;

					for (x = start; x <= stop; x++)
					{
						decode++;

						if (q <= end)
						{
							*q = *x;
							q++;
						}
					}
				}
				start = NULL;
				stop = NULL;

				p++;
				if (next2 == '\n')
					p++;
				break;
			}

			/* = elsewhere */
			pos = (unsigned char *) strchr(hexdigits, next1);
			if (pos == NULL)
				return -1;
			xl = (pos - (unsigned char *) hexdigits) * 16;

			pos = (unsigned char *) strchr(hexdigits, next2);
			if (pos == NULL)
				return -1;
			xl += (pos - (unsigned char *) hexdigits);

			stop = p;
			if (start != NULL)
			{
				unsigned char const *x;

				for (x = start; x < stop; x++)
				{
					decode++;

					if (q <= end)
					{
						*q = *x;
						q++;
					}
				}
			}
			start = NULL;
			stop = NULL;

			if (q <= end)
			{
				*q = xl;
				q++;
			}

			decode++;

			p += 2;

			break;

		  case ' ':
		  case '\t':
			if (start == NULL)
				start = p;
			break;

		  case '\r':
			break;

		  case '\n':
			if (stop == NULL)
				stop = p;
			if (start != NULL)
			{
				unsigned char const *x;

				for (x = start; x <= stop; x++)
				{
					decode++;

					if (q <= end)
					{
						*q = *x;
						q++;
					}
				}
			}

			if (p > in && *(p - 1) != '\r')
			{
				decode++;

				if (q <= end)
				{
					*q = '\n';
					q++;
				}
			}
			else
			{
				decode += 2;
				if (q <= end)
				{
					*q = '\r';
					q++;
				}
				if (q <= end)
				{
					*q = '\n';
					q++;
				}
			}

			start = NULL;
			stop = NULL;
			break;

		  default:
			if (start == NULL)
				start = p;
			stop = p;
			break;
		}
	}

	if (start != NULL)
	{
		unsigned char const *x;

		for (x = start; x < p; x++)
		{
			decode++;

			if (q <= end)
			{
				*q = *x;
				q++;
			}
		}
	}

	return decode;
}

#ifdef NEED_FAST_STRTOUL
/*
**  DKIM_STRTOUL -- convert string to unsigned long
**
**  Parameters:
**  	str -- string to convert
**  	endptr -- pointer to store string after value
**  	base -- base to convert from
**
**  Return value:
**  	Value of string as unsigned long
*/

unsigned long
dkim_strtoul(const char *str, char **endptr, int base)
{
	char start = '+';
	static char cutlim = ULONG_MAX % 10;
	char c;
	_Bool erange = FALSE;
	static unsigned long cutoff = ULONG_MAX / 10;
	unsigned long value = 0;
	const char *subj;
	const char *cur;

	if (base != 10)
		return strtoul(str, endptr, base);

	if (str == NULL)
	{
		errno = EINVAL;
		return value;
	}

	subj = str;

	while (*subj != '\0' && isspace(*subj))
		subj++;

	if (*subj == '-' || *subj == '+')
		start = *subj++;

	for (cur = subj; *cur >= '0' && *cur <= '9'; cur++)
	{
		if (erange)
			continue;

		c = *cur - '0';

		if ((value > cutoff) || (value == cutoff && c > cutlim))
		{
			erange = TRUE;
			continue;
		}

		value = (value * 10) + c;
	}

	if (cur == subj)
	{
		if (endptr != NULL)
			*endptr = (char *) str;
		errno = EINVAL;
		return 0;
	}

	if (endptr != NULL)
		*endptr = (char *) cur;

	if (erange)
	{
		errno = ERANGE;
		return ULONG_MAX;
	}

	if (start == '-')
		return -value;
	else
		return value;
}

/*
**  DKIM_STRTOULL -- convert string to unsigned long long
**
**  Parameters:
**  	str -- string to convert
**  	endptr -- pointer to store string after value
**  	base -- base to convert from
**
**  Return value:
**  	Value of string as unsigned long long
*/

unsigned long long
dkim_strtoull(const char *str, char **endptr, int base)
{
	char start = '+';
	char c;
	_Bool erange = FALSE;
	static char cutlim = ULLONG_MAX % 10;
	static unsigned long long cutoff = ULLONG_MAX / 10;
	unsigned long long value = 0;
	const char *subj;
	const char *cur;

	if (base != 10)
		return strtoull(str, endptr, base);

	if (str == NULL)
	{
		errno = EINVAL;
		return value;
	}

	subj = str;

	while (*subj && isspace(*subj))
		subj++;

	if (*subj == '-' || *subj == '+')
		start = *subj++;

	for (cur = subj; *cur >= '0' && *cur <= '9'; cur++)
	{
		if (erange)
			continue;

		c = *cur - '0';

		if ((value > cutoff) || (value == cutoff && c > cutlim))
		{
			erange = 1;
			continue;
		}

		value = (value * 10) + c;
	}

	if (cur == subj)
	{
		if (endptr != NULL)
			*endptr = (char *) str;
		errno = EINVAL;
		return 0;
	}

	if (endptr != NULL)
		*endptr = (char *) cur;

	if (erange != 0)
	{
		errno = ERANGE;
		return ULLONG_MAX;
	}

	if (start == '-')
		return -value;
	else
		return value;
}
#endif /* NEED_FAST_STRTOUL */

/*
**  DKIM_CHECK_DNS_REPLY -- see if a DNS reply is truncated or corrupt
**
**  Parameters:
**  	ansbuf -- answer buffer
**  	anslen -- number of bytes returned
**  	xclass -- expected class
**  	xtype -- expected type
**
**  Return value:
**  	2 -- reply not usable
**  	1 -- reply truncated but usable
**  	0 -- reply intact (but may not be what you want)
**  	-1 -- other error
*/

int
dkim_check_dns_reply(unsigned char *ansbuf, size_t anslen,
                     int xclass, int xtype)
{
	_Bool trunc = FALSE;
	int qdcount;
	int ancount;
	int n;
	uint16_t type = (uint16_t) -1;
	uint16_t class = (uint16_t) -1;
	unsigned char *cp;
	unsigned char *eom;
	HEADER hdr;
	unsigned char name[DKIM_MAXHOSTNAMELEN + 1];

	assert(ansbuf != NULL);

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
		(void) dn_expand((unsigned char *) ansbuf, eom, cp,
		                 (RES_UNC_T) name, sizeof name);

		if ((n = dn_skipname(cp, eom)) < 0)
			return 2;

		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
			return 2;

		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != xtype || class != xclass)
		return 0;

	/* if NXDOMAIN, return DKIM_STAT_NOKEY */
	if (hdr.rcode == NXDOMAIN)
		return 0;

	/* if truncated, we can't do it */
	if (hdr.tc)
		trunc = TRUE;

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return (trunc ? 2 : 0);

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) ansbuf, eom, cp,
		                   (RES_UNC_T) name, sizeof name)) < 0)
			return 2;

		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ + INT32SZ > eom)
			return 2;

		GETSHORT(type, cp);
		cp += INT16SZ; /* class */
		cp += INT32SZ; /* ttl */

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			if ((n = dn_expand((u_char *) ansbuf, eom, cp,
			                   (RES_UNC_T) name, sizeof name)) < 0)
				return 2;

			cp += n;
			continue;
		}
		else if (type != xtype)
		{
			return (trunc ? 1 : 0);
		}

		/* found a record we can use; break */
		break;
	}

	/* if ancount went below 0, there were no good records */
	if (ancount < 0)
		return (trunc ? 1 : 0);

	/* get payload length */
	if (cp + INT16SZ > eom)
		return 2;

	GETSHORT(n, cp);

	/*
	**  XXX -- maybe deal with a partial reply rather than require
	**  	   it all
	*/

	if (cp + n > eom)
		return 2;

	return (trunc ? 1 : 0);
}

/*
**  DKIM_MIN_TIMEVAL -- determine the timeout to apply before reaching
**                      one of two timevals
**
**  Parameters:
**  	t1 -- first timeout (absolute)
**  	t2 -- second timeout (absolute) (may be NULL)
**  	t -- final timeout (relative)
**  	which -- which of t1 and t2 hit first
**
**  Return value:
**  	None.
*/

void
dkim_min_timeval(struct timeval *t1, struct timeval *t2, struct timeval *t,
                 struct timeval **which)
{
	struct timeval *next;
	struct timeval now;

	assert(t1 != NULL);
	assert(t != NULL);

	if (t2 == NULL ||
	    t2->tv_sec > t1->tv_sec ||
	    (t2->tv_sec == t1->tv_sec && t2->tv_usec > t1->tv_usec))
		next = t1;
	else
		next = t2;

	(void) gettimeofday(&now, NULL);

	if (next->tv_sec < now.tv_sec ||
	    (next->tv_sec == now.tv_sec && next->tv_usec < now.tv_usec))
	{
		t->tv_sec = 0;
		t->tv_usec = 0;
	}
	else
	{
		t->tv_sec = next->tv_sec - now.tv_sec;
		if (next->tv_usec < now.tv_usec)
		{
			t->tv_sec--;
			t->tv_usec = next->tv_usec - now.tv_usec + 1000000;
		}
		else
		{
			t->tv_usec = next->tv_usec - now.tv_usec;
		}
	}

	if (which != NULL)
		*which = next;
}

/*
**  DKIM_COPY_ARRAY -- copy an array of char pointers
**
**  Parameters:
**  	in -- input array, must be NULL-terminated
**
**  Return value:
**  	A copy of "in" and its elements, or NULL on failure.
*/

const char **
dkim_copy_array(char **in)
{
	unsigned int c;
	unsigned int n;
	char **out;

	assert(in != NULL);

	for (n = 0; in[n] != NULL; n++)
		continue;

	out = malloc(sizeof(char *) * (n + 1));

	for (c = 0; c < n; c++)
	{
		out[c] = strdup(in[c]);
		if (out[c] == NULL)
		{
			for (n = 0; n < c; n++)
				free(out[n]);
			free(out);
			return NULL;
		}
	}

	out[c] = NULL;

	return (const char **) out;
}

/*
**  DKIM_CLOBBER_ARRAY -- clobber a cloned array of char pointers
**
**  Parameters:
**  	in -- input array, must be NULL-terminated
**
**  Return value:
**  	None.
*/

void
dkim_clobber_array(char **in)
{
	unsigned int n;

	assert(in != NULL);

	for (n = 0; in[n] != NULL; n++)
		free(in[n]);

	free(in);
}

/*
**  DKIM_STRISPRINT -- return TRUE iff a string contains only isprint() characters
**
**  Parameters:
**  	str -- string to evaluate
**
**  Return value:
**  	TRUE unless a non-isprint was found
*/

_Bool
dkim_strisprint(unsigned char *str)
{
	unsigned char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (!isprint(*p))
			return FALSE;
	}

	return TRUE;
}
