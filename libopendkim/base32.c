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
**
** Portions Copyright (c) 2010-2012, The Trusted Domain Project.
** All rights reserved.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dkim.h"

#define BLKSIZE_RAW 5
#define BLKSIZE_ENC 8

static const char cb32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/*
**  DKIM_BASE32_ENCODE -- encode a string using base32
**
**  Parameters:
**  	buf -- destination buffer
**  	buflen -- in: bytes available at buf
**                out: bytes used from "data"
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
dkim_base32_encode(char *buf, size_t *buflen, const void *data, size_t size)
{
	unsigned int lastbits;
	unsigned int padding;
	int iout = 0;
	int iin = 0;
	unsigned char *udata;

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

	/* append padding */
	lastbits = (size * 8) % 40;
	if (lastbits == 0)
		padding = 0;
	else if (lastbits == 8)
		padding = 6;
	else if (lastbits == 16)
		padding = 4;
	else if (lastbits == 24)
		padding = 3;
	else /* (lastbits == 32) */
		padding = 1;

	while (padding > 0 && iout < *buflen)
	{
		buf[iout++] = '=';
		padding--;
	}

	/* ensure NULL termination */
	buf[iout] = '\0';

	/* store number of bytes from data that was used */
	*buflen = iin;

	return iout;
}

#ifdef TEST
#include <openssl/sha.h>

int
main(int argc, char **argv)
{
	int x;
	size_t buflen;
	SHA_CTX sha;
	char buf[128];
	unsigned char shaout[SHA_DIGEST_LENGTH];

	memset(buf, '\0', sizeof buf);
	buflen = sizeof buf;

	SHA1_Init(&sha);
	SHA1_Update(&sha, argv[1], strlen(argv[1]));
	SHA1_Final(shaout, &sha);

	x = dkim_base32_encode(buf, &buflen, shaout, SHA_DIGEST_LENGTH);

	printf("%s (%d)\n", buf, x);

	return 0;
}
#endif /* TEST */
