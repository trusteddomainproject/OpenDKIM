/*
**  Copyright (c) 1999-2002, Sendmail Inc. and its suppliers.
**	All rights reserved.
** 
**  By using this file, you agree to the terms and conditions set
**  forth in the LICENSE file which can be found at the top level of
**  the sendmail distribution.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char ar_strl_c_id[] = "@(#)$Id: ar-strl.c,v 1.2 2009/08/03 18:22:04 cm-msk Exp $";
#endif /* !lint */

#include <sys/types.h>
#include <string.h>

/*
**  XXX the type of the length parameter has been changed
**  from size_t to ssize_t to avoid theoretical problems with negative
**  numbers passed into these functions.
**  The real solution to this problem is to make sure that this doesn't
**  happen, but for now we'll use this workaround.
*/

#if HAVE_STRLCPY == 0

/*
**  AR_STRLCPY -- size bounded string copy
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
**		if (sm_strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
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
ar_strlcpy(dst, src, size)
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
#endif /* HAVE_STRLCPY == 0 */

#if HAVE_STRLCAT == 0
/*
**  AR_STRLCAT -- size bounded string concatenation
**
**	This is a bounds-checking variant of strcat.
**	If strlen(dst) < size, then append at most size - strlen(dst) - 1
**	characters from the source string to the destination string,
**	nul terminating the result.  Otherwise, dst is not modified.
**
**	The result is the initial length of dst + the length of src.
**	You can detect overflow (not all of the characters in the
**	source string were copied) using the following idiom:
**
**		char *s, buf[BUFSIZ];
**		...
**		if (sm_strlcat(buf, s, sizeof(buf)) >= sizeof(buf))
**			goto overflow;
**
**	Parameters:
**		dst -- nul-terminated destination string buffer
**		src -- nul-terminated source string
**		size -- size of destination buffer
**
**	Returns:
**		total length of the string tried to create
**		(= initial length of dst + length of src)
*/

size_t
ar_strlcat(dst, src, size)
	register char *dst;
	register const char *src;
	ssize_t size;
{
	register ssize_t i, j, o;

	o = strlen(dst);
	if (size < o + 1)
		return o + strlen(src);
	size -= o + 1;
	for (i = 0, j = o; i < size && (dst[j] = src[i]) != 0; i++, j++)
		continue;
	dst[j] = '\0';
	if (src[i] == '\0')
		return j;
	else
		return j + strlen(src + i);
}
#endif /* HAVE_STRLCAT == 0 */
