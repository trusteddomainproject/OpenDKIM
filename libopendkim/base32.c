/*
** Copyright (c) 2006-2009 Bjorn Andersson <flex@kryo.se>,
** Erik Ekman <yarrick@kryo.se>
** Mostly rewritten 2009 J.A.Bezemer@opensourcepartners.nl
**
** Permission to use, copy, modify, and distribute this software for any
** purpose with or without fee is hereby granted, provided that the above
** copyright notice and this permission notice appear in all copies.
**
** THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
** WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
** ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
** WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
** ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
** OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base32.h"

#define BLKSIZE_RAW 5
#define BLKSIZE_ENC 8

static const char cb32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/*
**  BASE32_ENCODE -- encode a string using base32
**
**  Parameters:
**  	buf -- destination buffer
**  	buflen -- bytes available at buf (updated)
**  	data -- pointer to data to encode
**  	size -- bytes at "data" to encode
**
**  Return value:
**  	Length of encoding.
**
**  Notes:
**  	buf should be at least a byte more than *buflen to hold the trailing
**  	'\0'.
**
**  	*buflen is updated to count the number of bytes read from "data".
*/

int 
base32_encode(char *buf, size_t *buflen, const void *data, size_t size)
{
	unsigned char *udata;
	int iout = 0;
	int iin = 0;

	udata = (unsigned char *) data;

	for (;;)
	{
		if (iout >= *buflen || iin >= size)
			break;

		buf[iout] = cb32[((udata[iin] & 0xf8) >> 3)];
		iout++;

		if (iout >= *buflen || iin >= size)
		{
			iout--; 	/* previous char is useless */
			break;
		}

		buf[iout] = cb32[((udata[iin] & 0x07) << 2) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xc0) >> 6) : 0)];
		iin++;			/* 0 complete, iin = 1 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x3e) >> 1)];
		iout++;

		if (iout >= *buflen || iin >= size)
		{
			iout--;		/* previous char is useless */
			break;
		}
		buf[iout] = cb32[((udata[iin] & 0x01) << 4) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xf0) >> 4) : 0)];
		iin++;			/* 1 complete, iin = 2 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x0f) << 1) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0x80) >> 7) : 0)];
		iin++;			/* 2 complete, iin = 3 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x7c) >> 2)];
		iout++;

		if (iout >= *buflen || iin >= size)
		{
			iout--;		/* previous char is useless */
			break;
		}
		buf[iout] = cb32[((udata[iin] & 0x03) << 3) |
				  ((iin + 1 < size) ?
				   ((udata[iin + 1] & 0xe0) >> 5) : 0)];
		iin++;			/* 3 complete, iin = 4 */
		iout++;

		if (iout >= *buflen || iin >= size)
			break;
		buf[iout] = cb32[((udata[iin] & 0x1f))];
		iin++;			/* 4 complete, iin = 5 */
		iout++;
	}

	buf[iout] = '\0';

	/* store number of bytes from data that was used */
	*buflen = iin;

	return iout;
}
