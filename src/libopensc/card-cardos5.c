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

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "iso7816.h"
#include "cardctl.h"
#include "card-cardos5.h"

static struct sc_cardos5_am_byte ef_acl[] = {
	{ AM_EF_DELETE,			SC_AC_OP_DELETE },
	{ AM_EF_TERMINATE,		UINT_MAX },
	{ AM_EF_ACTIVATE,		SC_AC_OP_REHABILITATE },
	{ AM_EF_DEACTIVATE,		SC_AC_OP_INVALIDATE },
	{ AM_EF_WRITE,			SC_AC_OP_WRITE },
	{ AM_EF_UPDATE,			SC_AC_OP_UPDATE },
	{ AM_EF_READ,			SC_AC_OP_READ },
	{ AM_EF_INCREASE,		UINT_MAX },
	{ AM_EF_DECREASE,		UINT_MAX },
};

static struct sc_cardos5_am_byte df_acl[] = {
	{ AM_DF_DELETE_SELF,		SC_AC_OP_DELETE },
	{ AM_DF_TERMINATE,		UINT_MAX },
	{ AM_DF_ACTIVATE,		SC_AC_OP_REHABILITATE },
	{ AM_DF_DEACTIVATE,		SC_AC_OP_INVALIDATE },
	{ AM_DF_CREATE_DF_FILE,		SC_AC_OP_CREATE },
	{ AM_DF_CREATE_EF_FILE,		SC_AC_OP_CREATE },
	{ AM_DF_DELETE_CHILD,		UINT_MAX },
	{ AM_DF_PUT_DATA_OCI,		SC_AC_OP_CREATE },
	{ AM_DF_PUT_DATA_OCI_UPDATE,	SC_AC_OP_UPDATE },
	{ AM_DF_LOAD_EXECUTABLE,	UINT_MAX },
	{ AM_DF_PUT_DATA_FCI,		SC_AC_OP_CREATE },
};

static const int ef_acl_n = sizeof(ef_acl) / sizeof(struct sc_cardos5_am_byte);
static const int df_acl_n = sizeof(df_acl) / sizeof(struct sc_cardos5_am_byte);
static const struct sc_card_operations *iso_ops = NULL;
static const struct sc_card_operations *cardos4_ops = NULL;

static struct sc_card_operations cardos5_ops;

static struct sc_card_driver cardos5_drv = {
	"Atos CardOS",
	"cardos5",
	&cardos5_ops,
	NULL, 0, NULL
};

static struct sc_atr_table cardos5_atrs[] = {
	/* CardOS v5.0 */
	{ "3b:d2:18:00:81:31:fe:58:c9:01:14", NULL, NULL,
	  SC_CARD_TYPE_CARDOS_V5_0, 0, NULL},
	/* CardOS v5.3 */
	{ "3b:d2:18:00:81:31:fe:58:c9:03:16", NULL, NULL,
	  SC_CARD_TYPE_CARDOS_V5_3, 0, NULL},
	{ NULL, NULL, NULL, 0, 0, NULL }
};

struct cardos5_private_data {
	/* Current Security Environment Algorithm */
	unsigned int	cse_algorithm;
};

static int
cardos5_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, cardos5_atrs, &card->type) < 0)
		return 0;

	return 1;
}

static int
cardos5_init(sc_card_t *card)
{
	struct cardos5_private_data	*priv;
	unsigned int			 flags;

	priv = calloc(1, sizeof(*priv));
	if (priv == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	priv->cse_algorithm = UINT_MAX;
	card->drv_data = priv;

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_NONE |
	    SC_ALGORITHM_ONBOARD_KEY_GEN;

	card->name = "CardOS M5";
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->cla = 0x00;
	card->max_recv_size = 768;

	_sc_card_add_rsa_alg(card,  512, flags, 0);
	_sc_card_add_rsa_alg(card,  768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1280, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 1792, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	_sc_card_add_rsa_alg(card, 2304, flags, 0);
	_sc_card_add_rsa_alg(card, 2560, flags, 0);
	_sc_card_add_rsa_alg(card, 2816, flags, 0);
	_sc_card_add_rsa_alg(card, 3072, flags, 0);
	_sc_card_add_rsa_alg(card, 3328, flags, 0);
	_sc_card_add_rsa_alg(card, 3584, flags, 0);
	_sc_card_add_rsa_alg(card, 3840, flags, 0);
	_sc_card_add_rsa_alg(card, 4096, flags, 0);

	flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN;

	_sc_card_add_ec_alg(card, 192, flags, 0, NULL);
	_sc_card_add_ec_alg(card, 224, flags, 0, NULL);
	_sc_card_add_ec_alg(card, 256, flags, 0, NULL);
	_sc_card_add_ec_alg(card, 384, flags, 0, NULL);
	_sc_card_add_ec_alg(card, 512, flags, 0, NULL);

	return 0;
}

static int
cardos5_finish(sc_card_t *card)
{
	free(card->drv_data);
	card->drv_data = NULL;

	return SC_SUCCESS;
}

static int
cardos5_read_record(sc_card_t *card, unsigned int record_number, uint8_t *buf,
    size_t buf_len, unsigned long flags)
{
	struct sc_context	*ctx = card->ctx;
	sc_apdu_t		 apdu;
	int			 r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.cla = CARDOS5_READ_RECORD_CLA;
	apdu.ins = CARDOS5_READ_RECORD_INS;
	apdu.p1 = record_number;
	apdu.resp = buf;
	apdu.resplen = buf_len;
	apdu.le = buf_len;

	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 = 0x04;
	else if (flags & SC_RECORD_NEXT)
		apdu.p2 = 0x02;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(ctx, "command failed");
		return r;
	}

	return (int)apdu.resplen;
}

static int
parse_entry(struct sc_context *ctx, cardos5_buf_t *entries, uint8_t *entry_buf,
    uint16_t entry_len, uint8_t *next_offset)
{
	uint8_t		 tag;
	uint8_t		*tag_ptr;
	uint16_t	 tag_len;
	cardos5_buf_t	 entry;

	cardos5_buf_init(&entry, entry_buf, entry_len);

	while (entry.size - entry.bytes_used >= 2) {
		tag = entry.ptr[0];
		if (cardos5_get_tag(ctx, tag, &tag_ptr, &tag_len, &entry)) {
			sc_log(ctx, "asn1 error");
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}
		if (tag == FILE_ID_TAG) {
			if (tag_len != 2) {
				free(tag_ptr);
				sc_log(ctx, "wrong tag len");
				return SC_ERROR_UNKNOWN_DATA_RECEIVED;
			}
			if (entries->size - entries->bytes_used < 2) {
				free(tag_ptr);
				sc_log(ctx, "partial directory listing");
				return SC_ERROR_BUFFER_TOO_SMALL;
			}
			entries->ptr[0] = tag_ptr[0];
			entries->ptr[1] = tag_ptr[1];
			entries->ptr += 2;
			entries->bytes_used += 2;
		} else if (tag == FILE_NEXT_OFFSET_TAG) {
			if (tag_len != 1) {
				free(tag_ptr);
				sc_log(ctx, "wrong tag len");
				return SC_ERROR_UNKNOWN_DATA_RECEIVED;
			}
			*next_offset = tag_ptr[0];
		}
		free(tag_ptr);
	}

	/* make sure we parsed the complete directory entry */
	if (entry.bytes_used != entry.size) {
		sc_log(ctx, "only parsed %zu out of %zu directory entry",
		    entry.bytes_used, entry.size);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	return SC_SUCCESS;
}

static int
list_page(sc_card_t *card, cardos5_buf_t *entries, uint8_t offset,
    uint8_t *next_offset)
{
	struct sc_context	*ctx = card->ctx;
	sc_apdu_t		 apdu;
	uint8_t			 page_buf[256];
	uint8_t			*entry = NULL;
	uint16_t		 entry_len;
	cardos5_buf_t		 page;
	int			 r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.cla = CARDOS5_DIRECTORY_CLA;
	apdu.ins = CARDOS5_DIRECTORY_INS;
	apdu.p1 = CARDOS5_DIRECTORY_P1;
	apdu.p2 = offset;
	apdu.le = sizeof(page_buf);
	apdu.resp = page_buf;
	apdu.resplen = sizeof(page_buf);

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(ctx, "command failed");
		return r;
	}

	if (apdu.resplen > sizeof(page_buf)) {
		sc_log(ctx, "invalid apdu.resplen=%zu", (size_t)apdu.resplen);
		return SC_ERROR_WRONG_LENGTH;
	}

	cardos5_buf_init(&page, page_buf, apdu.resplen);

	while (cardos5_get_tag(ctx, DIR_ENTRY_TAG, &entry, &entry_len,
	    &page) == 0) {
		r = parse_entry(ctx, entries, entry, entry_len, next_offset);
		free(entry);
		if (r != SC_SUCCESS)
			return r;
	}

	/* make sure we parsed the complete directory page */
	if (page.bytes_used != page.size) {
		sc_log(ctx, "only parsed %zu out of %zu directory bytes",
		    page.bytes_used, page.size);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	return SC_SUCCESS;
}

static int
cardos5_list_files(sc_card_t *card, unsigned char *buf, size_t buflen)
{
	uint8_t		offset;
	uint8_t		next_offset;
	cardos5_buf_t	entries;
	int		r;

	next_offset = 0;
	cardos5_buf_init(&entries, buf, buflen);

	do {
		offset = next_offset;
		r = list_page(card, &entries, offset, &next_offset);
		if (r != SC_SUCCESS)
			return r;
	} while (offset != next_offset);

	/* return number of bytes used for extracted file IDs */
	return entries.bytes_used;
}

static int
parse_df_arl(sc_card_t *card, sc_file_t *file, const uint8_t *arl, size_t len)
{
	unsigned long	ref;
	unsigned int	ac;
	int		i;
	int		r;

	/*
	 * The MF is created with an ARL consisting of the sequence { 0x81,
	 * 0x00, 0x90, 0x00 }, meaning "allow everything". Recognise it, and
	 * call sc_file_add_acl_entry() accordingly.
	 */

	if (file->id == 0x3f00) {
		for (i = 0; i < df_acl_n; i++) {
			if (df_acl[i].op_byte != UINT_MAX) {
				r = sc_file_add_acl_entry(file,
				    df_acl[i].op_byte, SC_AC_NONE,
				    SC_AC_KEY_REF_NONE);
				if (r != SC_SUCCESS)
					return r;
			}
		}
		return SC_SUCCESS;
	}

	while (len >= 5) {
		/* This is needed to allow ACCUMULATE OBJECT DATA. */
		if (arl[0] == ARL_COMMAND_TAG) {
			if (len < 8)
				return SC_ERROR_WRONG_LENGTH;
			if (arl[6] == ARL_USER_AUTH_TAG) {
				size_t skip = arl[7];
				if (len < skip + 8)
					return SC_ERROR_WRONG_LENGTH;
				arl += skip;
				len -= skip;
			}
			arl += 8;
			len -= 8;
			continue;
		}

		if (arl[0] != ARL_ACCESS_MODE_BYTE_TAG ||
		    arl[1] != ARL_ACCESS_MODE_BYTE_LEN)
			return SC_ERROR_NO_CARD_SUPPORT;

		for (i = 0; i < df_acl_n; i++)
			if (df_acl[i].am_byte == arl[2])
				break;
		if (i == df_acl_n)
			return SC_ERROR_NO_CARD_SUPPORT;

		ref = SC_AC_KEY_REF_NONE;

		switch (arl[3]) {
		case ARL_ALWAYS_TAG:
			if (arl[4] != ARL_ALWAYS_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NONE;
			arl += 5;
			len -= 5;
			break;
		case ARL_NEVER_TAG:
			if (arl[4] != ARL_NEVER_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NEVER;
			arl += 5;
			len -= 5;
			break;
		case ARL_USER_AUTH_TAG:
			if (len < 11)
				return SC_ERROR_WRONG_LENGTH;
			if (arl[4] != ARL_USER_AUTH_LEN ||
			    arl[5] != CRT_TAG_PINREF ||
			    arl[6] != CRT_LEN_PINREF)
				return SC_ERROR_NO_CARD_SUPPORT;
			if (arl[8] != CRT_TAG_KUQ ||
			    arl[9] != CRT_LEN_KUQ ||
			    arl[10] != KUQ_USER_AUTH)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_CHV;
			ref = arl[7] & BACKTRACK_MASK;
			arl += 11;
			len -= 11;
			break;
		default:
			return SC_ERROR_NO_CARD_SUPPORT;
		}

		if (df_acl[i].op_byte != UINT_MAX) {
			r = sc_file_add_acl_entry(file, df_acl[i].op_byte, ac,
			    ref);
			if (r != SC_SUCCESS)
				return r;
		}
	}

	if (len != 0)
		return SC_ERROR_WRONG_LENGTH;

	return SC_SUCCESS;
}

static int
parse_ef_arl(sc_card_t *card, sc_file_t *file, const uint8_t *arl, size_t len)
{
	unsigned long	ref;
	unsigned int	ac;
	int		i;
	int		r;

	while (len >= 5) {
		if (arl[0] != ARL_ACCESS_MODE_BYTE_TAG ||
		    arl[1] != ARL_ACCESS_MODE_BYTE_LEN)
			return SC_ERROR_NO_CARD_SUPPORT;

		for (i = 0; i < ef_acl_n; i++)
			if (ef_acl[i].am_byte == arl[2])
				break;
		if (i == ef_acl_n)
			return SC_ERROR_NO_CARD_SUPPORT;

		ref = SC_AC_KEY_REF_NONE;

		switch (arl[3]) {
		case ARL_ALWAYS_TAG:
			if (arl[4] != ARL_ALWAYS_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NONE;
			arl += 5;
			len -= 5;
			break;
		case ARL_NEVER_TAG:
			if (arl[4] != ARL_NEVER_LEN)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_NEVER;
			arl += 5;
			len -= 5;
			break;
		case ARL_USER_AUTH_TAG:
			if (len < 11)
				return SC_ERROR_WRONG_LENGTH;
			if (arl[4] != ARL_USER_AUTH_LEN ||
			    arl[5] != CRT_TAG_PINREF ||
			    arl[6] != CRT_LEN_PINREF)
				return SC_ERROR_NO_CARD_SUPPORT;
			if (arl[8] != CRT_TAG_KUQ ||
			    arl[9] != CRT_LEN_KUQ ||
			    arl[10] != KUQ_USER_AUTH)
				return SC_ERROR_NO_CARD_SUPPORT;
			ac = SC_AC_CHV;
			ref = arl[7] & BACKTRACK_MASK;
			arl += 11;
			len -= 11;
			break;
		default:
			return SC_ERROR_NO_CARD_SUPPORT;
		}

		if (ef_acl[i].op_byte != UINT_MAX) {
			r = sc_file_add_acl_entry(file, ef_acl[i].op_byte, ac,
			    ref);
			if (r != SC_SUCCESS)
				return r;
		}
	}

	if (len != 0)
		return SC_ERROR_WRONG_LENGTH;

	return SC_SUCCESS;
}

static int
parse_arl(sc_card_t *card, sc_file_t *file, const uint8_t *arl, size_t len)
{
	switch (file->type) {
	case SC_FILE_TYPE_DF:
		return parse_df_arl(card, file, arl, len);
	case SC_FILE_TYPE_WORKING_EF:
		return parse_ef_arl(card, file, arl, len);
	default:
		sc_log(card->ctx, "invalid file type %d", file->type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
}

static int
cardos5_process_fci(struct sc_card *card, struct sc_file *file,
    const unsigned char *buf, size_t buflen)
{
	const uint8_t	*tag;
	size_t		 taglen;
	int		 r;

	if ((r = iso_ops->process_fci(card, file, buf, buflen)) != SC_SUCCESS)
		return r;

	tag = sc_asn1_find_tag(card->ctx, buf, buflen, 0xAB, &taglen);
	if (tag != NULL && taglen != 0)
		sc_file_set_sec_attr(file, tag, taglen);

	return SC_SUCCESS;
}

static int
cardos5_select_file(sc_card_t *card, const sc_path_t *path,
    sc_file_t **file_out)
{
	struct sc_context	*ctx = card->ctx;
	struct sc_file		*file = NULL;
	struct sc_apdu		 apdu;
	uint8_t			 buf[SC_MAX_APDU_BUFFER_SIZE];
	int			 r;

	if (path->type != SC_PATH_TYPE_PATH || path->len < 2 ||
	    path->value[0] != 0x3F || path->value[1] != 0x00) {
		sc_log(ctx, "invalid arguments");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(&buf, 0, sizeof(buf));
	memset(&apdu, 0, sizeof(apdu));
	apdu.ins = CARDOS5_SELECT_INS;

	if (path->len == 2) {
		/*
		 * only 0x3F00 supplied; keep it.
		 */
		apdu.p1 = CARDOS5_SELECT_P1_FILE_ID;
		apdu.lc = path->len;
		apdu.data = (unsigned char *)path->value;
		apdu.datalen = path->len;
	} else {
		/*
		 * skip 0x3F00; 'path' holds a complete path relative to the MF.
		 */
		apdu.p1 = CARDOS5_SELECT_P1_FULL_PATH;
		apdu.lc = path->len - 2;
		apdu.data = (unsigned char *)path->value + 2;
		apdu.datalen = path->len - 2;
	}


	if (file_out != NULL) {
		/* ask the card to return FCI metadata. */
		apdu.p2 = CARDOS5_SELECT_P2_FCI;
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 256;
		apdu.cse = SC_APDU_CASE_4_SHORT;
	} else {
		/* no metadata required. */
		apdu.p2 = CARDOS5_SELECT_P2_NO_RESPONSE;
		apdu.cse = SC_APDU_CASE_3_SHORT;
	}

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(ctx, "command failed");
		return r;
	}

	if (file_out == NULL)
		return SC_SUCCESS;

	if (apdu.resplen < 2 || apdu.resp[0] != ISO7816_TAG_FCI ||
	    (apdu.resp[1] != 0x81 && apdu.resp[1] != 0x82)) {
		sc_log(ctx, "invalid response");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	if ((file = sc_file_new()) == NULL) {
		sc_log(ctx, "out of memory");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	/*
	 * In CardOS 5.0 with FCI, the length is BER-TLV encoded.
	 */
	if (apdu.resp[1] == 0x81) {
		card->ops->process_fci(card, file,
		    (unsigned char *)apdu.resp + 3, apdu.resp[2]);
	} else if (apdu.resp[1] == 0x82) {
		int len = (apdu.resp[2] << 8) | apdu.resp[3];
		card->ops->process_fci(card, file,
		    (unsigned char *)apdu.resp + 4, (size_t)len);
	}

	r = parse_arl(card, file, file->sec_attr, file->sec_attr_len);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not parse arl");
	}

	*file_out = file;

	return SC_SUCCESS;
}

static int
construct_df_fcp(sc_card_t *card, const sc_file_t *df, cardos5_buf_t *fcp)
{
	const sc_acl_entry_t	*e = NULL;
	uint8_t			 df_size[2];
	uint8_t			 arl_buf[128];
	uint8_t			 cmd[4];
	cardos5_buf_t		 arl;
	int			 i;

	if (df->size > UINT16_MAX) {
		sc_log(card->ctx, "df->size too large: %zu", df->size);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	df_size[0] = (df->size >> 8) & 0xff;
	df_size[1] = (df->size & 0xff);

	if (cardos5_put_tag1(FCP_TAG_DESCRIPTOR, FCP_TYPE_DF, fcp) ||
	    cardos5_put_tag(FCP_TAG_DF_SIZE, df_size, sizeof(df_size), fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (df->namelen != 0 && cardos5_put_tag(FCP_TAG_DF_NAME, df->name,
	    df->namelen, fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	cardos5_buf_init(&arl, arl_buf, sizeof(arl_buf));

	e = sc_file_get_acl_entry(df, SC_AC_OP_UPDATE);
	if (e != NULL) {
		cmd[0] = 0x00;
		cmd[1] = CARDOS5_PUT_DATA_INS;
		cmd[2] = CARDOS5_PUT_DATA_ECD_P1;
		cmd[3] = CARDOS5_PUT_DATA_ECD_P2;
		if (cardos5_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
		    cardos5_add_acl(0xff, e->method, e->key_ref, &arl)) {
			return SC_ERROR_BUFFER_TOO_SMALL;
		}

	}

	/* Populate ARL. */
	for (i = 0; i < df_acl_n; i++) {
		unsigned int		 ac = SC_AC_NEVER;
		unsigned int		 keyref = UINT_MAX;

		if (df_acl[i].op_byte != UINT_MAX) {
			e = sc_file_get_acl_entry(df, df_acl[i].op_byte);
			if (e != NULL) {
				ac = e->method;
				keyref = e->key_ref;
			}
		}

		if (cardos5_add_acl(df_acl[i].am_byte, ac, keyref, &arl)) {
			sc_log(card->ctx, "could not add acl tag");
			return SC_ERROR_BUFFER_TOO_SMALL;
		}
	}

	/*
	 * Always allow lifecycle toggling through PHASE CONTROL for this DF.
	 */
	cmd[0] = CARDOS5_PHASE_CONTROL_CLA;
	cmd[1] = CARDOS5_PHASE_CONTROL_INS;
	cmd[2] = CARDOS5_PHASE_CONTROL_P1_TOGGLE;
	cmd[3] = CARDOS5_PHASE_CONTROL_P2_TOGGLE;
	if (cardos5_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    cardos5_put_tag0(ARL_ALWAYS_TAG, &arl)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	/*
	 * Always allow ACCUMULATE OBJECT DATA for new objects.
	 */
	cmd[0] = CARDOS5_ACCUMULATE_OBJECT_DATA_CLA;
	cmd[1] = CARDOS5_ACCUMULATE_OBJECT_DATA_INS;
	cmd[2] = CARDOS5_ACCUMULATE_OBJECT_DATA_P1_NEW;
	cmd[3] = 0x00;
	if (cardos5_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    cardos5_put_tag0(ARL_ALWAYS_TAG, &arl)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	/*
	 * Always allow ACCUMULATE OBJECT DATA for existing objects.
	 */
	cmd[2] = CARDOS5_ACCUMULATE_OBJECT_DATA_P1_APPEND;
	if (cardos5_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    cardos5_put_tag0(ARL_ALWAYS_TAG, &arl)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (cardos5_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	return SC_SUCCESS;
}

static int
construct_ef_fcp(sc_card_t *card, const sc_file_t *ef, cardos5_buf_t *fcp)
{
	uint8_t		file_type;
	uint8_t		ef_size[2];
	uint8_t		arl_buf[96];
	cardos5_buf_t	arl;
	int		i;

	if (ef->ef_structure == SC_FILE_EF_TRANSPARENT)
		file_type = FCP_TYPE_BINARY_EF;
	else if (ef->ef_structure == SC_FILE_EF_LINEAR_VARIABLE)
		file_type = FCP_TYPE_LINEAR_VARIABLE_EF;
	else {
		sc_log(card->ctx, "unsupported ef structure %u",
		    ef->ef_structure);
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (ef->size > UINT16_MAX) {
		sc_log(card->ctx, "ef->size too large: %zu", ef->size);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	ef_size[0] = (ef->size >> 8) & 0xff;
	ef_size[1] = (ef->size & 0xff);

	if (cardos5_put_tag1(FCP_TAG_DESCRIPTOR, file_type, fcp) ||
	    cardos5_put_tag(FCP_TAG_EF_SIZE, ef_size, sizeof(ef_size), fcp) ||
	    cardos5_put_tag0(FCP_TAG_EF_SFID, fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	cardos5_buf_init(&arl, arl_buf, sizeof(arl_buf));

	/* Populate ARL. */
	for (i = 0; i < ef_acl_n; i++) {
		const sc_acl_entry_t	*e = NULL;
		unsigned int		 ac = SC_AC_NEVER;
		unsigned int		 keyref = UINT_MAX;

		if (ef_acl[i].op_byte != UINT_MAX) {
			e = sc_file_get_acl_entry(ef, ef_acl[i].op_byte);
			if (e != NULL) {
				ac = e->method;
				keyref = (uint8_t)e->key_ref;
			}
		}

		if (cardos5_add_acl(ef_acl[i].am_byte, ac, keyref, &arl)) {
			sc_log(card->ctx, "could not add acl tag");
			return SC_ERROR_BUFFER_TOO_SMALL;
		}
	}

	if (cardos5_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	return SC_SUCCESS;
}

static int
construct_fcp(sc_card_t *card, const sc_file_t *file, cardos5_buf_t *buf)
{
	uint8_t		file_id[2];
	uint8_t		fcp_buf[128];
	cardos5_buf_t	fcp;
	int		r;

	cardos5_buf_init(&fcp, fcp_buf, sizeof(fcp_buf));

	switch (file->type) {
	case SC_FILE_TYPE_DF:
		r = construct_df_fcp(card, file, &fcp);
		break;
	case SC_FILE_TYPE_WORKING_EF:
		r = construct_ef_fcp(card, file, &fcp);
		break;
	default:
		sc_log(card->ctx, "unsupported file type %u", file->type);
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not construct fcp, r=%d", r);
		return r;
	}

	if (file->id < 0 || file->id > UINT16_MAX) {
		sc_log(card->ctx, "invalid file->id=%d", file->id);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	file_id[0] = (file->id >> 8) & 0xff;
	file_id[1] = (file->id & 0xff);

	if (cardos5_put_tag(FCP_TAG_FILEID, file_id, sizeof(file_id), &fcp)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (cardos5_put_tag(FCP_TAG_START, fcp_buf, fcp.bytes_used, buf)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	return SC_SUCCESS;
}

static int
cardos5_create_file(sc_card_t *card, sc_file_t *file)
{
	sc_apdu_t	apdu;
	uint8_t		fcp_buf[SC_MAX_APDU_BUFFER_SIZE];
	cardos5_buf_t	fcp;
	int		r;

	cardos5_buf_init(&fcp, fcp_buf, sizeof(fcp_buf));

	if ((r = construct_fcp(card, file, &fcp)) != SC_SUCCESS) {
		sc_log(card->ctx, "could not construct fcp");
		return r;
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_CREATE_FILE_INS;
	apdu.lc = fcp.bytes_used;
	apdu.datalen = fcp.bytes_used;
	apdu.data = fcp_buf;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_restore_security_env(sc_card_t *card, int se_num)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
cardos5_set_security_env(sc_card_t *card, const sc_security_env_t *env,
    int se_num)
{
	struct cardos5_private_data	*priv;
	sc_apdu_t			 apdu;
	uint8_t				 data[16];
	cardos5_buf_t			 buf;
	int				 r;

	priv = card->drv_data;
	if (priv == NULL) {
		sc_log(card->ctx, "inconsistent driver state");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	priv->cse_algorithm = UINT_MAX;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_INS;
	apdu.p1 = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P1_SET;

	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P2_DECIPHER;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = CARDOS5_MANAGE_SECURITY_ENVIRONMENT_P2_SIGN;
		break;
	default:
		sc_log(card->ctx, "invalid security operation");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	cardos5_buf_init(&buf, data, sizeof(data));

	if (cardos5_put_tag1(CRT_TAG_KEYREF, env->key_ref[0], &buf) ||
	    cardos5_put_tag1(CRT_TAG_KUQ, KUQ_DECRYPT, &buf)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	apdu.lc = apdu.datalen = buf.bytes_used;
	apdu.data = data;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	priv->cse_algorithm = env->algorithm;

	return SC_SUCCESS;
}

typedef struct {
	uint8_t *encoded_ptr;
	size_t	 encoded_len;
	size_t	 raw_len;
} coordinate_t;

static int
extract_coordinate(sc_card_t *card, coordinate_t *c, cardos5_buf_t *signature)
{
	if (signature->size - signature->bytes_used < c->raw_len ||
	    c->raw_len >= INT8_MAX)
		return SC_ERROR_BUFFER_TOO_SMALL;

	if (signature->ptr[0] & 0x80) {
		c->encoded_len = c->raw_len + 3;
		c->encoded_ptr = calloc(1, c->encoded_len);
		if (c->encoded_ptr == NULL) {
			sc_log(card->ctx, "malloc");
			return SC_ERROR_OUT_OF_MEMORY;
		}

		c->encoded_ptr[0] = 0x02;
		c->encoded_ptr[1] = (uint8_t)c->raw_len + 1;
		c->encoded_ptr[2] = 0x00; /* Padding byte. */

		memcpy(c->encoded_ptr + 3, signature->ptr, c->raw_len);
	} else {
		c->encoded_len = c->raw_len + 2;
		c->encoded_ptr = calloc(1, c->encoded_len);
		if (c->encoded_ptr == NULL) {
			sc_log(card->ctx, "malloc");
			return SC_ERROR_OUT_OF_MEMORY;
		}

		c->encoded_ptr[0] = 0x02;
		c->encoded_ptr[1] = (uint8_t)c->raw_len;

		memcpy(c->encoded_ptr + 2, signature->ptr, c->raw_len);
	}

	signature->ptr += c->raw_len;
	signature->bytes_used += c->raw_len;

	if (card->type == SC_CARD_TYPE_CARDOS_V5_0) {
		if (signature->size - signature->bytes_used < 2)
			return SC_ERROR_BUFFER_TOO_SMALL;
		signature->ptr += 2;
		signature->bytes_used += 2;
	}

	return SC_SUCCESS;
}

static int
get_point(const coordinate_t *X, const coordinate_t *Y,
    cardos5_buf_t *encoded_sig)
{
	uint8_t	*point;
	size_t	 point_len;

	point_len = X->encoded_len + Y->encoded_len;
	if (point_len < X->encoded_len || point_len > UINT16_MAX)
		return SC_ERROR_INVALID_ARGUMENTS;

	point = calloc(1, point_len);
	if (point == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(point, X->encoded_ptr, X->encoded_len);
	memcpy(point + X->encoded_len, Y->encoded_ptr, Y->encoded_len);

	if (cardos5_put_tag(0x30, point, point_len, encoded_sig)) {
		free(point);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	free(point);

	return SC_SUCCESS;
}

static int
encode_ec_sig(sc_card_t *card, uint8_t *sig, size_t siglen, size_t sigbufsiz)
{
	coordinate_t	 X;
	coordinate_t	 Y;
	uint8_t		*raw_sig_buf;
	size_t		 coordinate_raw_len;
	cardos5_buf_t	 raw_sig;
	cardos5_buf_t	 encoded_sig;
	int		 r;

	if (siglen < 4 || siglen > sigbufsiz || (siglen % 2) != 0) {
		sc_log(card->ctx, "invalid siglen=%zu, sigbufsiz=%zu", siglen,
		    sigbufsiz);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (card->type == SC_CARD_TYPE_CARDOS_V5_0)
		coordinate_raw_len = (siglen - 4) / 2;
	else if (card->type == SC_CARD_TYPE_CARDOS_V5_3)
		coordinate_raw_len = siglen / 2;
	else {
		sc_log(card->ctx, "invalid card type %d", card->type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	raw_sig_buf = calloc(1, siglen);
	if (raw_sig_buf == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	memcpy(raw_sig_buf, sig, siglen);
	memset(sig, 0, sigbufsiz);

	cardos5_buf_init(&raw_sig, raw_sig_buf, siglen);

	memset(&X, 0, sizeof(X));
	memset(&Y, 0, sizeof(Y));

	X.raw_len = Y.raw_len = coordinate_raw_len;

	if ((r = extract_coordinate(card, &X, &raw_sig)) ||
	    (r = extract_coordinate(card, &Y, &raw_sig))) {
		sc_log(card->ctx, "could not decode signature");
		goto bail;
	}

	cardos5_buf_init(&encoded_sig, sig, sigbufsiz);

	if ((r = get_point(&X, &Y, &encoded_sig))) {
		sc_log(card->ctx, "could not decode signature");
		goto bail;
	}

	r = (int)encoded_sig.bytes_used;

bail:
	free(X.encoded_ptr);
	free(Y.encoded_ptr);
	free(raw_sig_buf);

	return r;
}

static int
cardos5_decipher(sc_card_t *card, const unsigned char *data, size_t data_len,
    unsigned char *out, size_t outlen)
{
	sc_apdu_t	apdu;
	uint8_t		*payload;
	size_t		 payload_len;
	int		 r;

	if (SIZE_MAX - data_len < 1 || outlen < 2 || outlen > INT_MAX - 2) {
		sc_log(card->ctx, "invalid arguments data_len=%zu, outlen=%zu",
		    data_len, outlen);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	payload_len = data_len + 1;
	payload = calloc(1, payload_len);
	if (payload == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	/* payload[0] = 0x00 (Padding Indicator Byte) */
	memcpy(payload + 1, data, data_len);
	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_4_EXT;
	apdu.ins = CARDOS5_PERFORM_SECURITY_OPERATION_INS;
	apdu.p1 = CARDOS5_PERFORM_SECURITY_OPERATION_P1_DECIPHER;
	apdu.p2 = CARDOS5_PERFORM_SECURITY_OPERATION_P2_DECIPHER;
	apdu.data = payload;
	apdu.datalen = payload_len;
	apdu.lc = payload_len;
	apdu.resp = out + 1;
	apdu.resplen = outlen - 1;
	apdu.le = outlen - 1;

	r = sc_transmit_apdu(card, &apdu);

	free(payload);

	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	if (apdu.resplen + 1 > INT_MAX) {
		sc_log(card->ctx, "reply too large (%zu bytes)", apdu.resplen);
		return SC_ERROR_WRONG_LENGTH;
	}

	/*
	 * Restore leading zero stripped by the card -- unfortunately, there
	 * doesn't seem to be a way to prevent this.
	 */
	out[0] = 0x00;

	return (int)apdu.resplen + 1;
}

static int
cardos5_compute_signature(sc_card_t *card, const unsigned char *data,
    size_t datalen, unsigned char *out, size_t outlen)
{
	struct cardos5_private_data	*priv;
	sc_apdu_t			 apdu;
	int				 r;

	priv = card->drv_data;
	if (priv == NULL || priv->cse_algorithm == UINT_MAX) {
		sc_log(card->ctx, "inconsistent driver state");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (outlen < datalen) {
		sc_log(card->ctx, "invalid outlen %zu", outlen);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_4_EXT;
	apdu.ins = CARDOS5_PERFORM_SECURITY_OPERATION_INS;
	apdu.p1 = CARDOS5_PERFORM_SECURITY_OPERATION_P1_SIGN;
	apdu.p2 = CARDOS5_PERFORM_SECURITY_OPERATION_P2_SIGN;
	apdu.data = (unsigned char *)data;
	apdu.datalen = datalen;
	apdu.lc = datalen;
	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = outlen;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	if (apdu.resplen > INT_MAX) {
		sc_log(card->ctx, "reply too large (%zu bytes)", apdu.resplen);
		return SC_ERROR_WRONG_LENGTH;
	}

	if (priv->cse_algorithm == SC_ALGORITHM_RSA)
		return (int)apdu.resplen;
	else if (priv->cse_algorithm == SC_ALGORITHM_EC)
		return encode_ec_sig(card, out, apdu.resplen, outlen);

	sc_log(card->ctx, "unknown algorithm %d", priv->cse_algorithm);

	return SC_ERROR_INVALID_ARGUMENTS;
}

static int
accumulate_object_data(sc_card_t *card,
    struct sc_cardctl_cardos_acc_obj_info *args)
{
	sc_apdu_t	apdu;
	uint8_t		rbuf[64];
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_4_SHORT;
	apdu.cla = CARDOS5_ACCUMULATE_OBJECT_DATA_CLA;
	apdu.ins = CARDOS5_ACCUMULATE_OBJECT_DATA_INS;

	if (args->append == 0) {
		/* New object. Allocate + write. */
		apdu.p1 = CARDOS5_ACCUMULATE_OBJECT_DATA_P1_NEW;
	}

	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;
	apdu.le = sizeof(rbuf);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	if (apdu.resplen != sizeof(args->hash) + 2) {
		sc_log(card->ctx, "wrong reply length");
		return SC_ERROR_CARD_CMD_FAILED;
	}

	memcpy(&args->hash, apdu.resp + 2, sizeof(args->hash));

	return SC_SUCCESS;
}

static int
generate_key(sc_card_t *card,
    struct sc_cardctl_cardos5_genkey_info *args)
{
	sc_apdu_t	apdu;
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_GENERATE_KEY_INS;
	apdu.p1  = CARDOS5_GENERATE_KEY_P1_GENERATE;
	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
extract_key(sc_card_t *card, struct sc_cardctl_cardos5_genkey_info *args)
{
	sc_apdu_t	apdu;
	uint8_t		rbuf[768];
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_4_EXT;
	apdu.ins = CARDOS5_GENERATE_KEY_INS;
	apdu.p1  = CARDOS5_GENERATE_KEY_P1_EXTRACT;
	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	args->len = apdu.resplen;
	args->data = malloc(apdu.resplen);
	if (args->data == NULL)
		return SC_ERROR_MEMORY_FAILURE;

	memcpy(args->data, apdu.resp, apdu.resplen);

	return SC_SUCCESS;
}

static int
delete_key(sc_card_t *card, int *keyref)
{
	sc_apdu_t	apdu;
	int		r;

	if (keyref == NULL || *keyref < 0 || *keyref > UINT8_MAX) {
		sc_log(card->ctx, "invalid keyref");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/*
         * XXX We need to specify the backtracking bit in P2, otherwise the
         * command fails with 68 AA = Object not found. But why? We install key
         * objects directly on the 5015 DF, which the pkcs15init code has
         * selected just prior to calling us. Backtracking shouldn't be needed
         * in this case.
         */

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_1;
	apdu.cla = CARDOS5_DELETE_KEY_CLA;
	apdu.ins = CARDOS5_DELETE_KEY_INS;
	apdu.p1 = CARDOS5_DELETE_KEY_SIGN;
	apdu.p2 = *keyref | BACKTRACK_BIT; /*  XXX why? */

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

/*
 * We inform the card that the expected maximum length of a APDU's data field
 * is 0x0300 (768). This is needed for 4096-bit RSA keys, which are large, and
 * also allows us to perform certain operations (e.g. reads) with fewer
 * transactions.
 */
static int
init_card(sc_card_t *card)
{
	sc_apdu_t	apdu;
	int		r;

	/*
	 * XXX This APDU only takes effect after the next reset! P1 and P2 form
	 * the desired data field length (highest, lowest), which is stored by
	 * the card in its EEPROM.
	 */
	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_1;
	apdu.cla = CARDOS5_SET_DATA_FIELD_LENGTH_CLA;
	apdu.ins = CARDOS5_SET_DATA_FIELD_LENGTH_INS;
	apdu.p1 = 0x03;
	apdu.p2 = 0x00;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
put_data_ecd(sc_card_t *card, struct sc_cardctl_cardos_obj_info *args)
{
	sc_apdu_t	apdu;
	int		r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = CARDOS5_PUT_DATA_INS;
	apdu.p1 = CARDOS5_PUT_DATA_ECD_P1;
	apdu.p2 = CARDOS5_PUT_DATA_ECD_P2;
	apdu.lc = args->len;
	apdu.data = args->data;
	apdu.datalen = args->len;

	if ((r = sc_transmit_apdu(card, &apdu)) != SC_SUCCESS) {
		sc_log(card->ctx, "tx/rx error");
		return r;
	}

	if ((r = sc_check_sw(card, apdu.sw1, apdu.sw2)) != SC_SUCCESS) {
		sc_log(card->ctx, "command failed");
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_CARDOS_ACCUMULATE_OBJECT_DATA:
		return accumulate_object_data(card,
		    (struct sc_cardctl_cardos_acc_obj_info *)ptr);
	case SC_CARDCTL_CARDOS_GENERATE_KEY:
		return generate_key(card,
		    (struct sc_cardctl_cardos5_genkey_info *)ptr);
	case SC_CARDCTL_CARDOS_EXTRACT_KEY:
		return extract_key(card,
		    (struct sc_cardctl_cardos5_genkey_info *)ptr);
	case SC_CARDCTL_CARDOS_DELETE_KEY:
		return delete_key(card, (int *)ptr);
	case SC_CARDCTL_CARDOS_PUT_DATA_ECD:
		return put_data_ecd(card,
		    (struct sc_cardctl_cardos_obj_info *)ptr);
	case SC_CARDCTL_CARDOS_INIT_CARD:
		return init_card(card);
	case SC_CARDCTL_CARDOS_PUT_DATA_OCI:
	case SC_CARDCTL_CARDOS_PUT_DATA_SECI:
	case SC_CARDCTL_LIFECYCLE_GET:
	case SC_CARDCTL_LIFECYCLE_SET:
		return cardos4_ops->card_ctl(card, cmd, ptr);
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int
cardos5_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	data->pin_reference |= BACKTRACK_BIT;

	return iso_ops->pin_cmd(card, data, tries_left);
}

static int
cardos5_get_data(struct sc_card *card, unsigned int tag,  unsigned char *buf,
    size_t len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

struct sc_card_driver *
sc_get_cardos5_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	/* We rely on the CardOS 4 driver for some operations. */
	if (cardos4_ops == NULL)
		cardos4_ops = sc_get_cardos_driver()->ops;

	cardos5_ops = *iso_ops;
	cardos5_ops.match_card = cardos5_match_card;
	cardos5_ops.init = cardos5_init;
	cardos5_ops.finish = cardos5_finish;
	cardos5_ops.read_record = cardos5_read_record;
	cardos5_ops.process_fci = cardos5_process_fci;
	cardos5_ops.select_file = cardos5_select_file;
	cardos5_ops.create_file = cardos5_create_file;
	cardos5_ops.set_security_env = cardos5_set_security_env;
	cardos5_ops.restore_security_env = cardos5_restore_security_env;
	cardos5_ops.decipher = cardos5_decipher;
	cardos5_ops.compute_signature = cardos5_compute_signature;
	cardos5_ops.list_files = cardos5_list_files;
	cardos5_ops.check_sw = cardos4_ops->check_sw;
	cardos5_ops.card_ctl = cardos5_card_ctl;
	cardos5_ops.pin_cmd = cardos5_pin_cmd;
	cardos5_ops.logout  = cardos4_ops->logout;
	cardos5_ops.get_data = cardos5_get_data;

	return &cardos5_drv;
}
