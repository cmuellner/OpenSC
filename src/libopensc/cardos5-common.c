/*
 * Copyright (c) 2014, 2015 genua mbH.
 * All rights reserved.
 *
 * Written by Pedro Martelletto <pedro@ambientworks.net>.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Alternatively, this file may be distributed under the terms of the GNU
 * Lesser General Public License (LGPL) version 2.1.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "iso7816.h"
#include "cardctl.h"
#include "card-cardos5.h"

void
cardos5_buf_init(cardos5_buf_t *buf, uint8_t *ptr, size_t size)
{
	buf->ptr = ptr;
	buf->size = size;
	buf->bytes_used = 0;
}

int
cardos5_get_tag(struct sc_context *ctx, uint16_t tag, uint8_t **tag_content,
    uint16_t *tag_length, cardos5_buf_t *buf)
{
	const uint8_t	*tag_ptr;
	size_t		 tag_len; /* size_t version of tag_length */
	size_t		 delta;

	tag_ptr = sc_asn1_find_tag(ctx, buf->ptr, buf->size - buf->bytes_used,
	    tag, &tag_len);
	if (tag_ptr == NULL || tag_ptr < buf->ptr)
		return -1;

	delta = tag_ptr - buf->ptr;
	if (buf->size - buf->bytes_used < delta)
		return -1;
	buf->ptr += delta;
	buf->bytes_used += delta;

	if (tag_len > UINT16_MAX)
		return -1;
	*tag_length = (uint16_t)tag_len;
	if (buf->size - buf->bytes_used < *tag_length)
		return -1;

	if (tag_content != NULL) {
		if ((*tag_content = malloc(*tag_length)) == NULL)
			return -1;
		memcpy(*tag_content, buf->ptr, *tag_length);
		buf->ptr += *tag_length;
		buf->bytes_used += *tag_length;
	}

	return 0;
}

int
cardos5_put_tag(uint8_t tag, const void *tag_content, size_t tag_content_len,
    cardos5_buf_t *buf)
{
	int		 r;
	const uint8_t	*orig_ptr = buf->ptr;
	size_t		 delta;

	r = sc_asn1_put_tag(tag, (const uint8_t *)tag_content, tag_content_len,
	    buf->ptr, buf->size - buf->bytes_used, &buf->ptr);
	if (r == SC_SUCCESS) {
		delta = buf->ptr - orig_ptr;
		if (buf->ptr < orig_ptr || buf->size - buf->bytes_used < delta)
			return -1;
		buf->bytes_used += delta;
		return 0;
	}

	return -1;
}

int
cardos5_put_tag0(uint8_t tag, cardos5_buf_t *buf)
{
	return cardos5_put_tag(tag, NULL, 0, buf);
}

int
cardos5_put_tag1(uint8_t tag, uint8_t tag_value, cardos5_buf_t *buf)
{
	const uint8_t	tag_content[1] = { tag_value };

	return cardos5_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

int
cardos5_put_tag2(uint8_t tag, uint8_t a, uint8_t b, cardos5_buf_t *buf)
{
	const uint8_t	tag_content[2] = { a, b };

	return cardos5_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

int
cardos5_put_tag3(uint8_t tag, uint8_t a, uint8_t b, uint8_t c,
    cardos5_buf_t *buf)
{
	const uint8_t	tag_content[3] = { a, b, c };

	return cardos5_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

int
cardos5_add_acl(uint8_t am_byte, unsigned int ac, int key_ref,
    cardos5_buf_t *buf)
{
	uint8_t		crt_buf[16];
	cardos5_buf_t	crt;

	/*
	 * If am_byte == 0xff, we are complementing an ARL_COMMAND_TAG.
	 */ 
	if (am_byte != 0xff)
		if (cardos5_put_tag1(ARL_ACCESS_MODE_BYTE_TAG, am_byte, buf))
			return -1;

	switch (ac) {
	case SC_AC_NONE:
		/* SC_AC_NONE means operation ALWAYS allowed. */
		return cardos5_put_tag0(ARL_ALWAYS_TAG, buf);
	case SC_AC_NEVER:
		return cardos5_put_tag0(ARL_NEVER_TAG, buf);
	case SC_AC_CHV:
	case SC_AC_TERM:
	case SC_AC_AUT:
		if (key_ref < 0 || (key_ref & BACKTRACK_BIT) ||
		    key_ref > UINT8_MAX)
			return -1;

		cardos5_buf_init(&crt, crt_buf, sizeof(crt_buf));

		if (cardos5_put_tag1(CRT_TAG_PINREF, (uint8_t)key_ref, &crt) ||
		    cardos5_put_tag1(CRT_TAG_KUQ, KUQ_USER_AUTH, &crt) ||
		    cardos5_put_tag(ARL_USER_AUTH_TAG, crt_buf, crt.bytes_used,
		      buf))
			return -1;
		return 0;
	default:
		return -1;
	}
}
