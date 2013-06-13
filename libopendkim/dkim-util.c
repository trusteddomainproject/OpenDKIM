/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2012, 2013, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

/* libopendkim includes */
#include "dkim-internal.h"
#include "dkim-types.h"
#include "dkim-util.h"

/* prototypes */
extern void dkim_error __P((DKIM *, const char *, ...));

/*
**  DKIM_MALLOC -- allocate memory
**
**  Parameters:
**  	libhandle -- DKIM library context in which this is performed
**  	closure -- opaque closure handle for the allocation
**  	nbytes -- number of bytes desired
**
**  Return value:
**  	Pointer to allocated memory, or NULL on failure.
*/

void *
dkim_malloc(DKIM_LIB *libhandle, void *closure, size_t nbytes)
{
	assert(libhandle != NULL);

	if (libhandle->dkiml_malloc == NULL)
		return malloc(nbytes);
	else
		return libhandle->dkiml_malloc(closure, nbytes);
}

/*
**  DKIM_MFREE -- release memory
**
**  Parameters:
**  	dkim -- DKIM context in which this is performed
**  	closure -- opaque closure handle for the allocation
**  	ptr -- pointer to memory to be freed
**
**  Return value:
**  	None.
*/

void
dkim_mfree(DKIM_LIB *libhandle, void *closure, void *ptr)
{
	assert(libhandle != NULL);

	if (libhandle->dkiml_free == NULL)
		free(ptr);
	else
		libhandle->dkiml_free(closure, ptr);
}

/*
**  DKIM_STRDUP -- duplicate a string
**
**  Parameters:
**  	dkim -- DKIM handle
**  	str -- string to clone
**  	len -- bytes to copy (0 == copy to NULL byte)
**
**  Return value:
**  	Pointer to a new copy of "str" allocated from within the appropriate
**  	context, or NULL on failure.
*/

unsigned char *
dkim_strdup(DKIM *dkim, const unsigned char *str, size_t len)
{
	unsigned char *new;

	assert(dkim != NULL);
	assert(str != NULL);

	if (len == 0)
		len = strlen((char *) str);

	new = dkim_malloc(dkim->dkim_libhandle, dkim->dkim_closure, len + 1);
	if (new != NULL)
	{
		memcpy(new, str, len);
		new[len] = '\0';
	}
	else
	{
		dkim_error(dkim, "unable to allocate %d byte(s)", len + 1);
	}
	return new;
}

/*
**  DKIM_TMPFILE -- open a temporary file
**
**  Parameters:
**  	dkim -- DKIM handle
**  	fp -- descriptor (returned)
**  	keep -- if FALSE, unlink() the file once created
**
**  Return value:
**  	A DKIM_STAT_* constant.
*/

DKIM_STAT
dkim_tmpfile(DKIM *dkim, int *fp, _Bool keep)
{
	int fd;
	char *p;
	char path[MAXPATHLEN + 1];

	assert(dkim != NULL);
	assert(fp != NULL);

	if (dkim->dkim_id != NULL)
	{
		snprintf(path, MAXPATHLEN, "%s/dkim.%s.XXXXXX",
		         dkim->dkim_libhandle->dkiml_tmpdir, dkim->dkim_id);
	}
	else
	{
		snprintf(path, MAXPATHLEN, "%s/dkim.XXXXXX",
		         dkim->dkim_libhandle->dkiml_tmpdir);
	}

	for (p = path + strlen((char *) dkim->dkim_libhandle->dkiml_tmpdir) + 1;
	     *p != '\0';
	     p++)
	{
		if (*p == '/')
			*p = '.';
	}

	fd = mkstemp(path);
	if (fd == -1)
	{
		dkim_error(dkim, "can't create temporary file at %s: %s",
		           path, strerror(errno));
		return DKIM_STAT_NORESOURCE;
	}

	*fp = fd;

	if (!keep)
		(void) unlink(path);

	return DKIM_STAT_OK;
}

/*
**  DKIM_DSTRING_RESIZE -- resize a dynamic string (dstring)
**
**  Parameters:
**  	dstr -- DKIM_DSTRING handle
**  	len -- number of bytes desired
**
**  Return value:
**  	TRUE iff the resize worked (or wasn't needed)
**
**  Notes:
**  	This will actually ensure that there are "len" bytes available.
**  	The caller must account for the NULL byte when requesting a
**  	specific size.
*/

static _Bool
dkim_dstring_resize(struct dkim_dstring *dstr, int len)
{
	int newsz;
	unsigned char *new;
	DKIM *dkim;
	DKIM_LIB *lib;

	assert(dstr != NULL);
	assert(len > 0);

	if (dstr->ds_alloc >= len)
		return TRUE;

	dkim = dstr->ds_dkim;
	lib = dkim->dkim_libhandle;

	/* must resize */
	for (newsz = dstr->ds_alloc * 2;
	     newsz < len;
	     newsz *= 2)
	{
		/* impose ds_max limit, if specified */
		if (dstr->ds_max > 0 && newsz > dstr->ds_max)
		{
			if (len <= dstr->ds_max)
			{
				newsz = len;
				break;
			}

			dkim_error(dkim, "maximum string size exceeded");
			return FALSE;
		}

		/* check for overflow */
		if (newsz > INT_MAX / 2)
		{
			/* next iteration will overflow "newsz" */
			dkim_error(dkim, "internal string limit reached");
			return FALSE;
		}
	}

	new = dkim_malloc(lib, dkim->dkim_closure, newsz);
	if (new == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)", newsz);
		return FALSE;
	}

	memcpy(new, dstr->ds_buf, dstr->ds_alloc);

	dkim_mfree(lib, dkim->dkim_closure, dstr->ds_buf);

	dstr->ds_alloc = newsz;
	dstr->ds_buf = new;

	return TRUE;
}

/*
**  DKIM_DSTRING_NEW -- make a new dstring
**
**  Parameters:
**  	dkim -- DKIM handle
**  	len -- initial number of bytes
**  	maxlen -- maximum allowed length, including the NULL byte
**  	          (0 == unbounded)
**
**  Return value:
**  	A DKIM_DSTRING handle, or NULL on failure.
*/

struct dkim_dstring *
dkim_dstring_new(DKIM *dkim, int len, int maxlen)
{
	struct dkim_dstring *new;
	DKIM_LIB *lib;

	assert(dkim != NULL);

	/* fail on invalid parameters */
	if ((maxlen > 0 && len > maxlen) || len < 0)
		return NULL;

	lib = dkim->dkim_libhandle;

	if (len < BUFRSZ)
		len = BUFRSZ;

	new = dkim_malloc(lib, dkim->dkim_closure, sizeof(struct dkim_dstring));
	if (new == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           sizeof(struct dkim_dstring));
		return NULL;
	}

	new->ds_buf = dkim_malloc(lib, dkim->dkim_closure, len);
	if (new->ds_buf == NULL)
	{
		dkim_error(dkim, "unable to allocate %d byte(s)",
		           sizeof(struct dkim_dstring));
		dkim_mfree(lib, dkim->dkim_closure, new);
		return NULL;
	}

	memset(new->ds_buf, '\0', len);
	new->ds_alloc = len;
	new->ds_len = 0;
	new->ds_max = maxlen;
	new->ds_dkim = dkim;

	return new;
}

/*
**  DKIM_DSTRING_FREE -- destroy an existing dstring
**
**  Parameters:
**  	dstr -- DKIM_DSTRING handle to be destroyed
**
**  Return value:
**  	None.
*/

void
dkim_dstring_free(struct dkim_dstring *dstr)
{
	DKIM_LIB *lib;
	DKIM *dkim;

	assert(dstr != NULL);

	dkim = dstr->ds_dkim;
	lib = dkim->dkim_libhandle;

	dkim_mfree(lib, dkim->dkim_closure, dstr->ds_buf);
	dkim_mfree(lib, dkim->dkim_closure, dstr);
}

/*
**  DKIM_DSTRING_COPY -- copy data into a dstring
**
**  Parameters:
**  	dstr -- DKIM_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the copy succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkim_dstring_copy(struct dkim_dstring *dstr, unsigned char *str)
{
	int len;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str);

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dkim_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* copy */
	memcpy(dstr->ds_buf, str, len + 1);
	dstr->ds_len = len;

	return TRUE;
}

/*
**  DKIM_DSTRING_CAT -- append data onto a dstring
**
**  Parameters:
**  	dstr -- DKIM_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkim_dstring_cat(struct dkim_dstring *dstr, unsigned char *str)
{
	size_t len;
	size_t needed;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str);
	needed = dstr->ds_len + len;

	/* too big? */
	if (dstr->ds_max > 0 && needed >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= needed)
	{
		/* nope; try to resize */
		if (!dkim_dstring_resize(dstr, needed + 1))
			return FALSE;
	}

	/* append */
	memcpy(dstr->ds_buf + dstr->ds_len, str, len + 1);
	dstr->ds_len += len;

	return TRUE;
}

/*
**  DKIM_DSTRING_CAT1 -- append one byte onto a dstring
**
**  Parameters:
**  	dstr -- DKIM_DSTRING handle to update
**  	c -- input character
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkim_dstring_cat1(struct dkim_dstring *dstr, int c)
{
	int len;

	assert(dstr != NULL);

	len = dstr->ds_len + 1;

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!dkim_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_buf[dstr->ds_len++] = c;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  DKIM_DSTRING_CATN -- append 'n' bytes onto a dstring
**
**  Parameters:
**  	dstr -- DKIM_DSTRING handle to update
**  	str -- input string
**  	nbytes -- number of bytes to append
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
dkim_dstring_catn(struct dkim_dstring *dstr, unsigned char *str, size_t nbytes)
{
	size_t needed;

	assert(dstr != NULL);
	assert(str != NULL);

	needed = dstr->ds_len + nbytes;

	/* too big? */
	if (dstr->ds_max > 0 && needed >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= needed)
	{
		/* nope; try to resize */
		if (!dkim_dstring_resize(dstr, needed + 1))
			return FALSE;
	}

	/* append */
	memcpy(dstr->ds_buf + dstr->ds_len, str, nbytes);
	dstr->ds_len += nbytes;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  DKIM_DSTRING_GET -- retrieve data in a dstring
**
**  Parameters:
**  	dstr -- DKIM_STRING handle whose string should be retrieved
**
**  Return value:
**  	Pointer to the NULL-terminated contents of "dstr".
*/

unsigned char *
dkim_dstring_get(struct dkim_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_buf;
}

/*
**  DKIM_DSTRING_LEN -- retrieve length of data in a dstring
**
**  Parameters:
**  	dstr -- DKIM_STRING handle whose string should be retrieved
**
**  Return value:
**  	Number of bytes in a dstring.
*/

int
dkim_dstring_len(struct dkim_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_len;
}

/*
**  DKIM_DSTRING_BLANK -- clear out the contents of a dstring
**
**  Parameters:
**  	dstr -- DKIM_STRING handle whose string should be cleared
**
**  Return value:
**  	None.
*/

void
dkim_dstring_blank(struct dkim_dstring *dstr)
{
	assert(dstr != NULL);

	dstr->ds_len = 0;
	dstr->ds_buf[0] = '\0';
}

/*
**  DKIM_DSTRING_PRINTF -- write variable length formatted output to a dstring
**
**  Parameters:
**  	dstr -- DKIM_STRING handle to be updated
**  	fmt -- format
**  	... -- variable arguments
**
**  Return value:
**  	New size, or -1 on error.
*/

size_t
dkim_dstring_printf(struct dkim_dstring *dstr, char *fmt, ...)
{
	size_t len;
	size_t rem;
	va_list ap;
	va_list ap2;

	assert(dstr != NULL);
	assert(fmt != NULL);

	va_start(ap, fmt);
	va_copy(ap2, ap);
	rem = dstr->ds_alloc - dstr->ds_len;
	len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem, fmt, ap);
	va_end(ap);

	if (len > rem)
	{
		if (!dkim_dstring_resize(dstr, dstr->ds_len + len + 1))
		{
			va_end(ap2);
			return (size_t) -1;
		}

		rem = dstr->ds_alloc - dstr->ds_len;
		len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem,
		                fmt, ap2);
	}

	va_end(ap2);

	dstr->ds_len += len;

	return dstr->ds_len;
}
