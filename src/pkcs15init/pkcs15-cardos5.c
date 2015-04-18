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

#include "config.h"

#include <sys/types.h>

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef ENABLE_OPENSSL
#include <openssl/objects.h>
#include <openssl/ec.h>
#endif

#include "libopensc/opensc.h"
#include "libopensc/card-cardos5.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/cards.h"
#include "libopensc/asn1.h"
#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"
#include "pkcs15-init.h"
#include "profile.h"

#define CURVEDB	"curvedb"

typedef struct {
	size_t				bytes;
	struct sc_pkcs15_prkey_rsa	privkey;
	struct sc_pkcs15_pubkey_rsa	pubkey;
} rsa_keypair_t;

typedef struct {
	size_t				bytes;
	struct sc_pkcs15_prkey_ec	privkey;
	struct sc_pkcs15_pubkey_ec	pubkey;
} ec_keypair_t;

typedef struct {
	uint8_t	*ptr;
	size_t	 size;
	size_t	 bytes_used;
} buf_t;

static void
buf_init(buf_t *buf, uint8_t *ptr, size_t size)
{
	buf->ptr = ptr;
	buf->size = size;
	buf->bytes_used = 0;
}

static int
asn1_get_tag(struct sc_context *ctx, uint16_t tag, uint8_t **tag_content,
    uint16_t *tag_length, buf_t *buf)
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
	*tag_length = tag_len;
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

static int
asn1_put_tag(uint8_t tag, const void *tag_content, size_t tag_content_len,
    buf_t *buf)
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

static int
asn1_put_tag0(uint8_t tag, buf_t *buf)
{
	return asn1_put_tag(tag, NULL, 0, buf);
}

static int
asn1_put_tag1(uint8_t tag, uint8_t tag_value, buf_t *buf)
{
	const uint8_t	tag_content[1] = { tag_value };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
asn1_put_tag2(uint8_t tag, uint8_t a, uint8_t b, buf_t *buf)
{
	const uint8_t	tag_content[2] = { a, b };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
asn1_put_tag3(uint8_t tag, uint8_t a, uint8_t b, uint8_t c, buf_t *buf)
{
	const uint8_t	tag_content[3] = { a, b, c };

	return asn1_put_tag(tag, tag_content, sizeof(tag_content), buf);
}

static int
add_acl_tag(uint8_t am_byte, unsigned int ac, int key_ref, buf_t *buf)
{
	uint8_t	crt_buf[16];
	buf_t	crt;

	if (asn1_put_tag1(ARL_ACCESS_MODE_BYTE_TAG, am_byte, buf))
		return -1;

	switch (ac) {
	case SC_AC_NONE:
		/* SC_AC_NONE means operation ALWAYS allowed. */
		return asn1_put_tag0(ARL_ALWAYS_TAG, buf);
	case SC_AC_NEVER:
		return asn1_put_tag0(ARL_NEVER_TAG, buf);
	case SC_AC_CHV:
	case SC_AC_TERM:
	case SC_AC_AUT:
		if (key_ref < 0 || (key_ref & BACKTRACK_BIT) ||
		    key_ref > UINT8_MAX)
			return -1;

		buf_init(&crt, crt_buf, sizeof(crt_buf));

		if (asn1_put_tag1(CRT_TAG_PINREF, (uint8_t)key_ref, &crt) ||
		    asn1_put_tag1(CRT_TAG_KUQ, KUQ_USER_AUTH, &crt) ||
		    asn1_put_tag(ARL_USER_AUTH_TAG, crt_buf, crt.bytes_used,
		    buf))
			return -1;
		return 0;
	default:
		return -1;
	}
}

static int
store_pin(sc_profile_t *profile, sc_card_t *card,
    sc_pkcs15_auth_info_t *auth_info, int puk_id, const unsigned char *pin,
    size_t pin_len)
{
	struct sc_cardctl_cardos_obj_info	args;
	uint8_t					payload_buf[256];
	uint8_t					arl_buf[128];
	uint8_t					retries_buf[16];
	uint8_t					paddedpin[128];
	buf_t					payload;
	buf_t					arl;
	buf_t					retries_oci;
	unsigned int				maxlen;
	int					pin_ref;
	int					retries;
	int					r;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r < 0)
		return r;

	maxlen = profile->pin_maxlen;
	if (maxlen > sizeof(paddedpin))
		maxlen = sizeof(paddedpin);
	if (pin_len > maxlen || profile->pin_pad_char > UINT8_MAX) {
		sc_log(card->ctx, "invalid parameters: pin_len=%zu, "
		    "pin_pad_char=0x%x", pin_len, profile->pin_pad_char);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memcpy(paddedpin, pin, pin_len);
	while (pin_len < maxlen)
		paddedpin[pin_len++] = (uint8_t)profile->pin_pad_char;

	pin = paddedpin;
	pin_ref = auth_info->attrs.pin.reference;
	if (pin_ref < 0 || pin_ref > UINT8_MAX) {
		sc_log(card->ctx, "invalid pin_ref=%d", pin_ref);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* The 0x0f limit is imposed by the device .*/
	retries = sc_profile_get_pin_retries(profile, pin_ref);
	if (retries < 0 || retries > 0x0f) {
		sc_log(card->ctx, "invalid number of retries %d", retries);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (asn1_put_tag1(CRT_TAG_PINREF, (uint8_t)pin_ref, &payload) ||
	    asn1_put_tag3(CRT_TAG_OBJPARAM, OBJPARAM_NOBACKTRACK, 0, 0,
	    &payload) || asn1_put_tag1(CRT_TAG_CU, CU_USER_AUTH, &payload) ||
	    asn1_put_tag1(CRT_TAG_KUQ, KUQ_USER_AUTH, &payload) ||
	    asn1_put_tag2(CRT_TAG_ALGO_TYPE, ALGO_TYPE_PIN, 0, &payload) ||
	    asn1_put_tag1(CRT_TAG_LIFECYCLE, LIFECYCLE_OPERATIONAL, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&retries_oci, retries_buf, sizeof(retries_buf));

	if (asn1_put_tag1(OCI_TAG_RETRIES, retries, &retries_oci)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&arl, arl_buf, sizeof(arl_buf));

	if (add_acl_tag(AM_KEY_USE, SC_AC_NONE, -1, &arl) ||
	    add_acl_tag(AM_KEY_CHANGE, SC_AC_CHV, pin_ref, &arl) ||
	    (puk_id != -1 && add_acl_tag(AM_KEY_RESET_RETRY_CTR, SC_AC_CHV,
	    puk_id, &arl))) {
		sc_log(card->ctx, "could not add acl tag");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (asn1_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, &payload) ||
	    asn1_put_tag(CRT_TAG_RETRIES, retries_buf, retries_oci.bytes_used,
	    &payload) || asn1_put_tag(CRT_TAG_KEYDATA, pin, pin_len,
	    &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	args.data = payload_buf;
	args.len = payload.bytes_used;

	return sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_OCI, &args);
}

static int
cardos5_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_file_t *df)
{
	struct sc_cardctl_cardos_obj_info	 args;
	struct sc_card				*card = p15card->card;
	struct sc_file				*file = NULL;
	uint8_t					 payload_buf[8];
	buf_t					 payload;
	int					 r;

	r = sc_pkcs15init_create_file(profile, p15card, df);
	if (r != SC_SUCCESS)
		return r;

	r = sc_select_file(card, &df->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	/* XXX do we need to specify an ARL for this SE object? */
	if (asn1_put_tag1(CRT_DO_KEYREF, 0x01, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	args.data = payload_buf;
	args.len = payload.bytes_used;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "couldn't switch card to admin lifecycle");
		return r;
	}

	r = sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_SECI, &args);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "couldn't create empty SE");
		return r;
	}

	r = sc_profile_get_file(profile, CURVEDB, &file);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "profile doesn't define curve database");
		return SC_SUCCESS; /* curvedb is optional */
	}

	r = sc_pkcs15init_create_file(profile, p15card, file);
	sc_file_free(file);
	if (r != SC_SUCCESS)
		sc_log(card->ctx, "couldn't create curve database");

	return r;
}

static int
cardos5_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_file_t *df, sc_pkcs15_object_t *pin_obj, const unsigned char *pin,
    size_t pin_len, const unsigned char *puk, size_t puk_len)
{
	sc_pkcs15_auth_info_t	*auth_info;
	sc_pkcs15_auth_info_t	 puk_info;
	struct sc_card		*card = p15card->card;
	int			 puk_id = -1;
	int			 r;

	if (pin == 0 || pin_len == 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	auth_info = (sc_pkcs15_auth_info_t *)pin_obj->data;
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	r = sc_select_file(card, &df->path, NULL);
	if (r < 0)
		return r;

	if (puk != 0 && puk_len != 0) {
		sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK,
		    &puk_info);
		if (INT_MAX - auth_info->attrs.pin.reference < 2) {
			sc_log(card->ctx, "invalid pin %d",
			    auth_info->attrs.pin.reference);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		puk_info.attrs.pin.reference = puk_id =
		    auth_info->attrs.pin.reference + 1;
		r = store_pin(profile, card, &puk_info, -1, puk,
		    puk_len);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, "could not store puk, r=%d", r);
			return r;
		}
	}

	return store_pin(profile, card, auth_info, puk_id, pin, pin_len);
}

static uint32_t	public_exponent = 0x010001; /* 65537 */

static void
fill_in_dummy_rsa_key(rsa_keypair_t *rsa, uint8_t *dummy_data, size_t kbits)
{
	memset(rsa, 0x00, sizeof(*rsa));
	rsa->bytes = kbits / 8;

	rsa->pubkey.modulus.data = dummy_data;
	rsa->pubkey.modulus.len = rsa->bytes;
	rsa->pubkey.exponent.data = (unsigned char *)&public_exponent;
	rsa->pubkey.exponent.len = 3; /* XXX */

	/*
	 * >= 2048-bit keys follow the Chinese Remainder Theorem format. Note
	 * that the card expects Q > P.
	 */
	if (rsa->bytes > 256) {
		rsa->privkey.p.data = dummy_data;
		rsa->privkey.p.len = (rsa->bytes >> 1) - 1;
		rsa->privkey.q.data = dummy_data;
		rsa->privkey.q.len = (rsa->bytes >> 1) + 1;
		rsa->privkey.iqmp.data = dummy_data;
		rsa->privkey.iqmp.len = (rsa->bytes >> 1);
		rsa->privkey.dmp1.data = dummy_data;
		rsa->privkey.dmp1.len = (rsa->bytes >> 1) - 1;
		rsa->privkey.dmq1.data = dummy_data;
		rsa->privkey.dmq1.len = (rsa->bytes >> 1) + 1;
	} else {
		rsa->privkey.modulus.data = dummy_data;
		rsa->privkey.modulus.len = rsa->bytes;
		rsa->privkey.d.data = dummy_data;
		rsa->privkey.d.len = rsa->bytes;
	}
}

static void
fill_in_dummy_ec_key(ec_keypair_t *ec, uint8_t *dummyQ, uint8_t *dummyD,
    size_t kbits)
{
	memset(ec, 0x00, sizeof(*ec));

	ec->bytes = kbits / 8;

	dummyQ[0] = 0x04; /* uncompressed format */
	ec->pubkey.ecpointQ.value = dummyQ;
	ec->pubkey.ecpointQ.len = ec->bytes * 2 + 1;

	ec->privkey.privateD.data = dummyD;
	ec->privkey.privateD.len = ec->bytes;
}

static int
push_obj(sc_card_t *card, const uint8_t *obj, size_t len, uint8_t *key_sha256)
{
	struct sc_cardctl_cardos_acc_obj_info	args;
	uint8_t					payload_buf[128];
	size_t					done;
	size_t					n;
	int					r;

	if (len > UINT16_MAX) {
		sc_log(card->ctx, "invalid len %zu", len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	for (done = 0; done < len; done += n) {
		buf_t payload = { payload_buf, sizeof(payload_buf), 0 };

		if (done == 0) {
			uint8_t len_hi = (uint8_t)(len >> 8);
			uint8_t len_lo = (uint8_t)(len & 0xFF);
			if (asn1_put_tag2(0x80, len_hi, len_lo, &payload)) {
				sc_log(card->ctx, "asn1 error");
				return SC_ERROR_BUFFER_TOO_SMALL;
			}
			args.append = 0; /* allocate new object */
		} else
			args.append = 1; /* appending to existing object */

		n = len - done;
		if (n > 64)
			n = 64;

		if (asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_DATA_TAG,
		    obj + done, n, &payload)) {
			sc_log(card->ctx, "asn1 error");
			return SC_ERROR_BUFFER_TOO_SMALL;
		}

		args.data = payload_buf;
		args.len = payload.bytes_used;

		r = sc_card_ctl(card, SC_CARDCTL_CARDOS_ACCUMULATE_OBJECT_DATA,
		    &args);
		if (r != SC_SUCCESS)
			return r;
	}

	if (key_sha256 != NULL)
		memcpy(key_sha256, args.hash, 32);

	return SC_SUCCESS;
}

/* add a key Control Reference template (CRT) to a buf_t. */
static int
add_key_crt(int key_id, int algo, int active, int pubkey, buf_t *b)
{
	uint8_t	changeable;
	uint8_t	lifecycle;
	uint8_t	kuq;
	uint8_t	algo_type1;
	uint8_t	algo_type2;

	if (active) {
		changeable = OBJPARAM_UNCHANGEABLE;
		lifecycle = LIFECYCLE_OPERATIONAL;
	} else {
		changeable = OBJPARAM_CHANGEABLE;
		lifecycle = LIFECYCLE_CREATION;
	}

	if (pubkey)
		kuq = KUQ_ENCRYPT;
	else
		kuq = KUQ_DECRYPT;

	if (algo == SC_ALGORITHM_RSA) {
		algo_type1 = ALGO_TYPE_RSA;
		algo_type2 = ALGO_TYPE_PARAM;
	} else {
		algo_type1 = ALGO_TYPE_EC;
		algo_type2 = 0;
	}

	if (key_id < 0 || key_id > UINT8_MAX)
		return -1;

	if (asn1_put_tag1(CRT_DO_KEYREF, (uint8_t)key_id, b) ||
	    asn1_put_tag3(CRT_TAG_OBJPARAM, OBJPARAM_NOBACKTRACK, changeable, 0,
	    b) || asn1_put_tag1(CRT_TAG_CU, CU_CIPHER | CU_SIGN, b) ||
	    asn1_put_tag1(CRT_TAG_KUQ, kuq, b) ||
	    asn1_put_tag2(CRT_TAG_ALGO_TYPE, algo_type1, algo_type2, b) ||
	    asn1_put_tag1(CRT_TAG_LIFECYCLE, lifecycle, b))
		return -1;

	return 0;
}

static int
store_privkey(sc_card_t *card, int key_id, int algo, int active, int pin_id,
    const uint8_t *hash)
{
	struct sc_cardctl_cardos_obj_info	args;
	uint8_t					payload_buf[256];
	uint8_t					arl_buf[128];
	uint8_t					cmd[4];
	buf_t					payload;
	buf_t					arl;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(key_id, algo, active, 0, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&arl, arl_buf, sizeof(arl_buf));

	memset(cmd, 0, sizeof(cmd));
	cmd[1] = CARDOS5_GENERATE_KEY_INS;
	cmd[2] = CARDOS5_GENERATE_KEY_P1_EXTRACT;

	if (asn1_put_tag(ARL_COMMAND_TAG, cmd, sizeof(cmd), &arl) ||
	    asn1_put_tag0(ARL_ALWAYS_TAG, &arl)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (add_acl_tag(AM_KEY_USE, SC_AC_CHV, pin_id, &arl) ||
	    add_acl_tag(AM_KEY_CHANGE, SC_AC_CHV, pin_id, &arl) ||
	    add_acl_tag(AM_KEY_OCI_UPD, SC_AC_CHV, pin_id, &arl) ||
	    add_acl_tag(AM_KEY_DELETE, SC_AC_CHV, pin_id, &arl)) {
		sc_log(card->ctx, "could not add acl tag");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	if (asn1_put_tag(FCP_TAG_ARL, arl_buf, arl.bytes_used, &payload) ||
	    asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_HASH_TAG, hash, 32,
	    &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;

	return sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_OCI, &args);
}

static int
cardos_put_rsa_privkey(sc_profile_t *profile, struct sc_pkcs15_card *p15card,
    sc_pkcs15_prkey_info_t *keyinfo, const rsa_keypair_t *rsa, int active)
{
	struct sc_card	*card = p15card->card;
	uint8_t		 hash[32];
	uint8_t		 payload_buf[2048];
	uint8_t		 object_buf[2048];
	buf_t		 payload;
	buf_t		 object;
	int		 pin_ref;
	int		 r;

	pin_ref = sc_pkcs15init_get_pin_reference(p15card, profile,
	    SC_AC_SYMBOLIC, SC_PKCS15INIT_USER_PIN);
	if (pin_ref < 0 || pin_ref & BACKTRACK_BIT) {
		sc_log(card->ctx, "invalid pin_ref=%d", pin_ref);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	/* >= 2048-bit keys follow the Chinese Remainder Theorem format. */
	if (rsa->bytes > 256) {
		if (asn1_put_tag(RSA_PRIVKEY_PRIME_P_TAG, rsa->privkey.p.data,
		    rsa->privkey.p.len, &payload))
			goto asn1_error;

		if (asn1_put_tag(RSA_PRIVKEY_PRIME_Q_TAG, rsa->privkey.q.data,
		    rsa->privkey.q.len, &payload))
			goto asn1_error;

		if (asn1_put_tag(RSA_PRIVKEY_QINV_TAG, rsa->privkey.iqmp.data,
		    rsa->privkey.iqmp.len, &payload))
			goto asn1_error;

		if (asn1_put_tag(RSA_PRIVKEY_REMAINDER1_TAG,
		    rsa->privkey.dmp1.data, rsa->privkey.dmp1.len, &payload))
			goto asn1_error;

		if (asn1_put_tag(RSA_PRIVKEY_REMAINDER2_TAG,
		    rsa->privkey.dmq1.data, rsa->privkey.dmq1.len, &payload))
			goto asn1_error;
	} else {
		if (asn1_put_tag(RSA_PRIVKEY_MODULUS_TAG,
		    rsa->privkey.modulus.data, rsa->privkey.modulus.len,
		    &payload))
			goto asn1_error;

		if (asn1_put_tag(RSA_PRIVKEY_EXPONENT_TAG,
		    rsa->privkey.d.data, rsa->privkey.d.len, &payload))
			goto asn1_error;
	}

	buf_init(&object, object_buf, sizeof(object_buf));

	if (asn1_put_tag(CONSTRUCTED_DATA_TAG, payload_buf, payload.bytes_used,
	    &object))
		goto asn1_error;

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_privkey(card, keyinfo->key_reference, SC_ALGORITHM_RSA,
	    active, pin_ref, hash);

asn1_error:
	sc_log(card->ctx, "asn1 error");

	return SC_ERROR_BUFFER_TOO_SMALL;
}

static int
extract_curve_oid(struct sc_card *card, const sc_pkcs15_prkey_info_t *keyinfo,
    buf_t *payload)
{
	struct sc_pkcs15_ec_parameters	*param;

	if (keyinfo->params.len != sizeof(struct sc_pkcs15_ec_parameters)) {
		sc_log(card->ctx, "invalid keyinfo->params.len=%zu",
		    keyinfo->params.len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	param = (struct sc_pkcs15_ec_parameters *)keyinfo->params.data;
	if (param == NULL) {
		sc_log(card->ctx, "invalid param=%p", param);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (payload->size - payload->bytes_used < param->der.len) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(payload->ptr, param->der.value, param->der.len);
	payload->ptr += param->der.len;
	payload->bytes_used += param->der.len;

	return SC_SUCCESS;
}

static int
put_ec_privkey(sc_profile_t *profile, struct sc_pkcs15_card *p15card,
    sc_pkcs15_prkey_info_t *keyinfo, const ec_keypair_t *ec, int active)
{
	struct sc_card *card = p15card->card;
	unsigned char	hash[32];
	unsigned char	payload_buf[256];
	unsigned char	object_buf[256];
	buf_t		payload;
	buf_t		object;
	int		pin_ref;
	int		r;

	pin_ref = sc_pkcs15init_get_pin_reference(p15card, profile,
	    SC_AC_SYMBOLIC, SC_PKCS15INIT_USER_PIN);
	if (pin_ref < 0 || pin_ref & BACKTRACK_BIT) {
		sc_log(card->ctx, "invalid pin reference 0x%x", pin_ref);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if ((r = extract_curve_oid(card, keyinfo, &payload)) != SC_SUCCESS)
		return r;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	if (asn1_put_tag(ECC_PRIVKEY_D, ec->privkey.privateD.data,
	    ec->privkey.privateD.len, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&object, object_buf, sizeof(object_buf));

	if (asn1_put_tag(CONSTRUCTED_DATA_TAG, payload_buf, payload.bytes_used,
	    &object)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_privkey(card, keyinfo->key_reference, SC_ALGORITHM_EC,
	    active, pin_ref, hash);
}

static int
store_pubkey(sc_card_t *card, int key_id, int algo, unsigned char *hash)
{
	struct sc_cardctl_cardos_obj_info	args;
	uint8_t					payload_buf[256];
	buf_t					payload;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(key_id, algo, 0, 1, &payload) ||
	    asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_HASH_TAG, hash, 32,
	    &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;

	return sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_OCI, &args);
}

static int
cardos_put_rsa_pubkey(struct sc_pkcs15_card *p15card,
    sc_pkcs15_prkey_info_t *keyinfo, rsa_keypair_t *rsa)
{
	struct sc_card	*card = p15card->card;
	uint8_t		 hash[32];
	uint8_t		 payload_buf[768];
	uint8_t		 object_buf[768];
	buf_t		 payload;
	buf_t		 object;
	int		 r;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (asn1_put_tag(RSA_PUBKEY_MODULUS, rsa->pubkey.modulus.data,
	    rsa->pubkey.modulus.len, &payload))
		goto asn1_error;

	if (asn1_put_tag(RSA_PUBKEY_EXPONENT, rsa->pubkey.exponent.data,
	    rsa->pubkey.exponent.len, &payload))
		goto asn1_error;

	buf_init(&object, object_buf, sizeof(object_buf));

	if (asn1_put_tag(CONSTRUCTED_DATA_TAG, payload_buf, payload.bytes_used,
	    &object))
		goto asn1_error;

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_pubkey(card, keyinfo->key_reference, SC_ALGORITHM_RSA,
	    hash);

asn1_error:
	sc_log(card->ctx, "asn1 error");

	return SC_ERROR_BUFFER_TOO_SMALL;
}

static int
put_ec_pubkey(struct sc_pkcs15_card *p15card, sc_pkcs15_prkey_info_t *keyinfo,
    ec_keypair_t *ec)
{
	struct sc_card *card = p15card->card;
	unsigned char	hash[32];
	unsigned char	payload_buf[256];
	unsigned char	object_buf[256];
	buf_t		payload;
	buf_t		object;
	int		r;

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if ((r = extract_curve_oid(card, keyinfo, &payload)) != SC_SUCCESS)
		return r;

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		return r;

	if (asn1_put_tag(ECC_PUBKEY_Y, ec->pubkey.ecpointQ.value,
	    ec->pubkey.ecpointQ.len, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	buf_init(&object, object_buf, sizeof(object_buf));

	if (asn1_put_tag(CONSTRUCTED_DATA_TAG, payload_buf, payload.bytes_used,
	    &object)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	r = push_obj(card, object_buf, object.bytes_used, hash);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push key, r=%d", r);
		return r;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, NULL);
	if (r != SC_SUCCESS)
		return r;

	return store_pubkey(card, keyinfo->key_reference, SC_ALGORITHM_EC,
	    hash);
}

static int
extract_rsa_pubkey(sc_card_t *card, struct sc_pkcs15_prkey_info *keyinfo,
    sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info	args;
	uint16_t				taglen;
	uint8_t					payload_buf[256];
	uint8_t					crt_buf[24];
	size_t					modulus_bytes;
	buf_t					crt;
	buf_t					payload;
	buf_t					keybuf;
	int					r;

	modulus_bytes = keyinfo->modulus_length / 8;
	if (modulus_bytes == 0 || modulus_bytes > 1024) {
		sc_log(card->ctx, "invalid modulus %zu", modulus_bytes);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	buf_init(&crt, crt_buf, sizeof(crt_buf));
	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_RSA, 1, 1, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;
	r = sc_card_ctl(card, SC_CARDCTL_CARDOS_EXTRACT_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "key extraction failed, r=%d", r);
		return r;
	}

	buf_init(&keybuf, args.data, args.len);

	if (asn1_get_tag(card->ctx, 0x7F49, NULL, &taglen, &keybuf))
		goto parse_error;

	if (asn1_get_tag(card->ctx, RSA_PUBKEY_MODULUS,
	    &pubkey->u.rsa.modulus.data,
	    (uint16_t *)&pubkey->u.rsa.modulus.len, &keybuf))
		goto parse_error;

	if (pubkey->u.rsa.modulus.len != modulus_bytes)
		goto parse_error;

	if (asn1_get_tag(card->ctx, RSA_PUBKEY_EXPONENT,
	    &pubkey->u.rsa.exponent.data,
	    (uint16_t *)&pubkey->u.rsa.exponent.len, &keybuf))
		goto parse_error;

	free(args.data);

	pubkey->algorithm = SC_ALGORITHM_RSA;

	return SC_SUCCESS;

parse_error:
	free(args.data);
	sc_log(card->ctx, "couldn't parse rsa pubkey");

	return SC_ERROR_OBJECT_NOT_VALID;
}

/* Components of a public key as produced by the card. */
static const uint16_t pubkey_parts[] = {
	0x7F49,
	ECC_PUBKEY_OID,
	ECD_PRIME_P,
	ECD_COEFFICIENT_A,
	ECD_COEFFICIENT_B,
	ECD_GENERATOR_POINT_G,
	ECD_ORDER_R,
};

static const int n_pubkey_parts = sizeof(pubkey_parts) / sizeof(uint16_t);

static int
extract_ec_pubkey(sc_card_t *card, sc_pkcs15_prkey_info_t *keyinfo,
    sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info	 args;
	struct sc_ec_params			*ecp = NULL;
	uint8_t					 payload_buf[768];
	uint8_t					 crt_buf[24];
	buf_t					 payload;
	buf_t					 crt;
	buf_t					 keybuf;
	int					 i;
	int					 r;

	buf_init(&crt, crt_buf, sizeof(crt_buf));
	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_EC, 1, 1, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
		sc_log(card->ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;

	r = sc_card_ctl(card, SC_CARDCTL_CARDOS_EXTRACT_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "key extraction failed, r=%d", r);
		return r;
	}

	ecp = calloc(1, sizeof(*ecp));
	if (ecp == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	pubkey->alg_id = calloc(1, sizeof(struct sc_algorithm_id));
	if (pubkey->alg_id == NULL) {
		sc_log(card->ctx, "calloc");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	buf_init(&keybuf, args.data, args.len);

	/* Skip parts we are not interested in. */
	for (i = 0; i < n_pubkey_parts; i++) {
		uint16_t taglen;

		if (pubkey_parts[i] == ECC_PUBKEY_OID) {
			uint8_t	*oid, *encoded_oid_buf;
			buf_t	 encoded_oid;

			if (asn1_get_tag(card->ctx, ECC_PUBKEY_OID, &oid,
			    &taglen, &keybuf)) {
				sc_log(card->ctx, "couldn't get oid");
				goto parse_error;
			}

			encoded_oid_buf = calloc(1, taglen + 2);
			if (encoded_oid_buf == NULL) {
				sc_log(card->ctx, "calloc");
				goto parse_error;
			}

			buf_init(&encoded_oid, encoded_oid_buf, taglen + 2);

			if (asn1_put_tag(ECC_PUBKEY_OID, oid, taglen,
			    &encoded_oid)) {
				sc_log(card->ctx, "couldn't encode oid");
				free(encoded_oid_buf);
				goto parse_error;
			}

			ecp->der_len = encoded_oid.bytes_used;
			ecp->der = encoded_oid_buf;
			ecp->type = 1;

			pubkey->u.ec.params.der.value = calloc(1, ecp->der_len);
			if (pubkey->u.ec.params.der.value == NULL) {
				sc_log(card->ctx, "calloc");
				free(encoded_oid_buf);
				goto parse_error;
			}

			memcpy(pubkey->u.ec.params.der.value, ecp->der,
			    ecp->der_len);
			pubkey->u.ec.params.der.len = ecp->der_len;
		} else {
			if (asn1_get_tag(card->ctx, pubkey_parts[i], NULL,
			    &taglen, &keybuf)) {
				sc_log(card->ctx, "couldn't parse ec pubkey "
				    "(0x%x)", pubkey_parts[i]);
				goto parse_error;
			}

			if (i > 0) {
				keybuf.ptr += taglen;
				keybuf.bytes_used += taglen;
			}
		}
	}

	if (asn1_get_tag(card->ctx, ECC_PUBKEY_Y, &pubkey->u.ec.ecpointQ.value,
	    (uint16_t *)&pubkey->u.ec.ecpointQ.len, &keybuf)) {
		sc_log(card->ctx, "couldn't parse ec pubkey");
		goto parse_error;
	}

	free(args.data);

	pubkey->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->algorithm = SC_ALGORITHM_EC;
	pubkey->alg_id->params = ecp;

	sc_pkcs15_fix_ec_parameters(card->ctx, &pubkey->u.ec.params);

	return SC_SUCCESS;

parse_error:
	free(args.data);
	free(ecp);
	return SC_ERROR_OBJECT_NOT_VALID;
}

static int
generate_rsa_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info args;
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *keyinfo = obj->data;
	unsigned char dummy_key_data[512], payload_buf[256];
	unsigned char crt_buf[24]; /* Control Reference Template */
	buf_t crt = { crt_buf, sizeof(crt_buf), 0 };
	buf_t payload = { payload_buf, sizeof(payload_buf), 0 };
	struct sc_file *file = NULL;
	size_t keybits;
	rsa_keypair_t rsa;
	int r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA)
		return SC_ERROR_NOT_SUPPORTED;

	if ((keybits = keyinfo->modulus_length & ~7UL) > 4096) {
		sc_log(ctx, "unsupported key size %zu", keybits);
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, &file);
	if (r) {
		sc_log(ctx, "sc_select_file failed, r=%d", r);
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	sc_file_free(file);
	if (r) {
		sc_log(ctx, "sc_pkcs15init_authenticate failed, r=%d", r);
		return r;
	}

	memset(dummy_key_data, 0xFF, sizeof(dummy_key_data));
	fill_in_dummy_rsa_key(&rsa, dummy_key_data, keybits);

	r = cardos_put_rsa_privkey(profile, p15card, keyinfo, &rsa, 0);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put privkey, r=%d", r);
		return r;
	}

	/*
	 * CardOS 5 requires an additional public key stub for key generation.
	 */
	if ((r = cardos_put_rsa_pubkey(p15card, keyinfo, &rsa)) != SC_SUCCESS) {
		sc_log(ctx, "could not put pubkey, r=%d", r);
		return r;
	}

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_RSA, 0, 0, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
		sc_log(ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;
	r = sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_GENERATE_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "key generation failed, r=%d", r);
		return r;
	}

	memset(pubkey, 0, sizeof(*pubkey));
	r = extract_rsa_pubkey(p15card->card, keyinfo, pubkey);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "key extraction failed, r=%d", r);
		if (pubkey->u.rsa.modulus.data != NULL)
			free(pubkey->u.rsa.modulus.data);
		if (pubkey->u.rsa.exponent.data != NULL)
			free(pubkey->u.rsa.exponent.data);
		return r;
	}

	return SC_SUCCESS;
}

#ifdef ENABLE_OPENSSL
static int
load_curve(int nid, int asn1_flag, uint8_t **data, size_t *data_len)
{
	BIO			*mem = NULL;
	char			*mem_ptr;
	long			 mem_len;
	EC_GROUP		*group = NULL;
	point_conversion_form_t	 form = POINT_CONVERSION_UNCOMPRESSED;
	int			 r = 1;

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL)
		goto out;

	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL)
		goto out;

	EC_GROUP_set_asn1_flag(group, asn1_flag);
	EC_GROUP_set_point_conversion_form(group, form);

	if (i2d_ECPKParameters_bio(mem, group) == 0)
		goto out;

	mem_len = BIO_get_mem_data(mem, &mem_ptr);
	if (mem_len < 0)
		goto out;

	*data_len = (size_t)mem_len;
	*data = malloc(*data_len);
	if (*data == NULL)
		goto out;

	memcpy(*data, mem_ptr, *data_len);

	r = 0;
out:
	if (mem != NULL)
		BIO_free(mem);
	if (group != NULL)
		EC_GROUP_free(group);

	return r;
}
#endif /* ENABLE_OPENSSL */

struct obj {
	uint8_t		*data;
	uint16_t	 len;
};

struct curve_parameters {
	struct obj	oid;
	struct obj	p;
	struct obj	a;
	struct obj	b;
	struct obj	g;
	struct obj	r;
	struct obj	f;
};

static int
decode_curve_parameters(sc_card_t *card, uint8_t *curve_der,
    size_t curve_der_len, struct curve_parameters *param)
{
	uint8_t		*tag = NULL;
	uint16_t	 taglen;
	buf_t		 der;
	int		 r = SC_ERROR_OBJECT_NOT_VALID;

	buf_init(&der, curve_der, curve_der_len);

#define SEQUENCE_TAG (SC_ASN1_TAG_SEQUENCE | SC_ASN1_TAG_CONSTRUCTED)

	if (asn1_get_tag(card->ctx, SEQUENCE_TAG, NULL, &taglen, &der))
		goto out;

	/* XXX What is the meaning of this INTEGER tag set to 1? */
	if (asn1_get_tag(card->ctx, SC_ASN1_TAG_INTEGER, &tag, &taglen, &der) ||
	    taglen != 1 || tag[0] != 0x01)
		goto out;

	/* OID and P are grouped in a sequence. */
	if (asn1_get_tag(card->ctx, SEQUENCE_TAG, NULL, &taglen, &der) ||
	    asn1_get_tag(card->ctx, SC_ASN1_TAG_OBJECT, &param->oid.data,
	    &param->oid.len, &der) || asn1_get_tag(card->ctx,
	    SC_ASN1_TAG_INTEGER, &param->p.data, &param->p.len, &der))
		goto out;

	/* A and B are grouped in a sequence. */
	if (asn1_get_tag(card->ctx, SEQUENCE_TAG, NULL, &taglen, &der) ||
	    asn1_get_tag(card->ctx, SC_ASN1_TAG_OCTET_STRING, &param->a.data,
	    &param->a.len, &der) || asn1_get_tag(card->ctx,
	    SC_ASN1_TAG_OCTET_STRING, &param->b.data, &param->b.len, &der))
		goto out;

	free(tag);
	tag = NULL;

	/* Some curves have an optional seed value: skip it. */
	if (der.ptr[0] == SC_ASN1_TAG_BIT_STRING && asn1_get_tag(card->ctx,
	    SC_ASN1_TAG_BIT_STRING, &tag, &taglen, &der))
		goto out;

	/* G, R and F are ungrouped, but appear sequentially. */
	if (asn1_get_tag(card->ctx, SC_ASN1_TAG_OCTET_STRING, &param->g.data,
	    &param->g.len, &der) || asn1_get_tag(card->ctx, SC_ASN1_TAG_INTEGER,
	    &param->r.data, &param->r.len, &der) || asn1_get_tag(card->ctx,
	    SC_ASN1_TAG_INTEGER, &param->f.data, &param->f.len, &der))
		goto out;

	/* Make sure that we consumed the whole buffer. */
	if (der.size != der.bytes_used)
		goto out;

	r = SC_SUCCESS;
out:
	if (tag != NULL)
		free(tag);

	return r;
}

static int
decode_curve_oid(sc_card_t *card, uint8_t *curve_oid, size_t curve_oid_len,
    struct curve_parameters *param)
{
	buf_t	oid;

	/* free oid obtained by decode_curve_parameters() */
	free(param->oid.data);
	param->oid.data = NULL;

	buf_init(&oid, curve_oid, curve_oid_len);

	if (asn1_get_tag(card->ctx, SC_ASN1_TAG_OBJECT, &param->oid.data,
	    &param->oid.len, &oid))
		return SC_ERROR_OBJECT_NOT_VALID;

	return SC_SUCCESS;
}

static int
push_curve_parameters(struct sc_card *card, const struct curve_parameters *p,
    uint8_t ecd_id)
{
	struct sc_cardctl_cardos_obj_info	args;
	uint8_t		sha256[32];
	uint8_t		ecd_buf[512];
	uint8_t		obj_buf[512];
	uint8_t		payload_buf[512];
	buf_t		ecd;
	buf_t		obj;
	buf_t		payload;
	int		r;

	/*
	 * First, we build an Elliptic Curve Domain object with the curve
	 * parameters obtained from the curve's DER file.
	 */

	buf_init(&ecd, ecd_buf, sizeof(ecd_buf));

        if (asn1_put_tag(ECD_CURVE_OID, p->oid.data, p->oid.len, &ecd) ||
	    asn1_put_tag(ECD_PRIME_P, p->p.data, p->p.len, &ecd) ||
	    asn1_put_tag(ECD_COEFFICIENT_A, p->a.data, p->a.len, &ecd) ||
	    asn1_put_tag(ECD_COEFFICIENT_B, p->b.data, p->b.len, &ecd) ||
	    asn1_put_tag(ECD_GENERATOR_POINT_G, p->g.data, p->g.len, &ecd) ||
	    asn1_put_tag(ECD_ORDER_R, p->r.data, p->r.len, &ecd) ||
	    asn1_put_tag(ECD_CO_FACTOR_F, p->f.data, p->f.len, &ecd))
		return SC_ERROR_BUFFER_TOO_SMALL;

	/*
	 * We then wrap this ECD object inside a CONSTRUCTED_DATA_TAG object.
	 * We push this object to the card and retrieve its SHA256 hash.
	 */

	buf_init(&obj, obj_buf, sizeof(obj_buf));

        if (asn1_put_tag(CONSTRUCTED_DATA_TAG, ecd_buf, ecd.bytes_used, &obj))
		return SC_ERROR_BUFFER_TOO_SMALL;

	r = push_obj(card, obj_buf, obj.bytes_used, sha256);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "could not push ecd, r=%d", r);
		return r;
	}

	/*
	 * Finally, we build the APDU payload (containing the hash) and send it.
	 */

	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (asn1_put_tag1(CRT_DO_KEYREF, ecd_id, &payload) ||
	    asn1_put_tag1(CRT_TAG_ALGO_TYPE, 0x0D, &payload) ||
	    asn1_put_tag(CARDOS5_ACCUMULATE_OBJECT_HASH_TAG, sha256,
	    sizeof(sha256), &payload))
		return SC_ERROR_BUFFER_TOO_SMALL;

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;

	return sc_card_ctl(card, SC_CARDCTL_CARDOS_PUT_DATA_ECD, &args);
}

#ifndef ENABLE_OPENSSL
static int
install_ecd(sc_card_t *card, sc_file_t *curvedb, const char *named_curve,
    const char *entry, uint8_t ecd_id)
{
	sc_log(card->ctx, "openssl not compiled in: not installing ecd");
	return SC_SUCCESS;
}
#else
static int
install_ecd(sc_card_t *card, sc_file_t *curvedb, const char *named_curve,
    const char *entry, uint8_t ecd_id)
{

	uint8_t			*curve_der = NULL;
	uint8_t			*curve_oid = NULL;
	size_t			 curve_der_len;
	size_t			 curve_oid_len;
	struct curve_parameters	 param;
	int			 curve_nid;
	int			 r = SC_ERROR_OBJECT_NOT_VALID;

	memset(&param, 0, sizeof(param));

	curve_nid = OBJ_sn2nid(named_curve);
	if (curve_nid == 0 || load_curve(curve_nid, OPENSSL_EC_NAMED_CURVE,
	    &curve_oid, &curve_oid_len) || load_curve(curve_nid, 0,
	    &curve_der, &curve_der_len)) {
		sc_log(card->ctx, "couldn't extract curve from openssl");
		goto out;
	}

	if (decode_curve_parameters(card, curve_der, curve_der_len, &param) ||
	    decode_curve_oid(card, curve_oid, curve_oid_len, &param)) {
		sc_log(card->ctx, "couldn't decode curve parameters");
		goto out;
	}

	r = push_curve_parameters(card, &param, ecd_id);
	if (r != SC_SUCCESS)
		sc_log(card->ctx, "failed to install ecd object");

out:
	if (curve_der != NULL)
		free(curve_der);
	if (curve_oid != NULL)
		free(curve_oid);
	if (param.oid.data != NULL)
		free(param.oid.data);
	if (param.p.data != NULL)
		free(param.p.data);
	if (param.a.data != NULL)
		free(param.a.data);
	if (param.b.data != NULL)
		free(param.b.data);
	if (param.g.data != NULL)
		free(param.g.data);
	if (param.r.data != NULL)
		free(param.r.data);
	if (param.f.data != NULL)
		free(param.f.data);

	return r;
}
#endif /* !ENABLE_OPENSSL */

/*
 * For Elliptic Curve keys, we need to make sure the card knows about the curve
 * and its parameters. In CardOS 5, an elliptic curve is defined by an Elliptic
 * Curve Domain (ECD) object. These objects can only be installed, and not read.
 * In order to keep track of configured curves, we keep a "curvedb" file on the
 * card with a list of ECD objects. Each entry on this list consists of a
 * string of the form "named_curve/curve_oid", as in "brainpoolP512r1/06:09:2b:
 * 24:03:03:02:08:01:01:0d". Curves found on this list are assumed to have a
 * backing ECD object configured on the card.
 */
static int
lookup_ecd(sc_profile_t *profile, sc_card_t *card,
    const sc_pkcs15_prkey_info_t *keyinfo)
{
	struct sc_pkcs15_ec_parameters	*param;
	sc_file_t			*curvedb = NULL;
	char				 entry[128];
	char				 buf[128];
	char				 tmp[4];
	uint8_t				 ecd_id = 1;
	size_t				 i;
	int				 n;
	int				 r;

	if (keyinfo->params.len != sizeof(struct sc_pkcs15_ec_parameters)) {
		sc_log(card->ctx, "invalid keyinfo->params.len=%zu",
		    keyinfo->params.len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	param = (struct sc_pkcs15_ec_parameters *)keyinfo->params.data;
	if (param == NULL || param->named_curve == NULL ||
	    param->der.value == NULL) {
		sc_log(card->ctx, "invalid param=%p", param);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	strlcpy(entry, param->named_curve, sizeof(entry));
	strlcat(entry, "/", sizeof(entry));

	for (i = 0; i < param->der.len; i++) {
		n = snprintf(tmp, sizeof(tmp), "%s%02x", i == 0 ? "" : ":",
		    param->der.value[i]);
		if (n < 0 || (size_t)n >= sizeof(tmp)) {
			sc_log(card->ctx, "snprintf failed");
			return 0;
		}
		strlcat(entry, tmp, sizeof(entry));
	}

	r = sc_profile_get_file(profile, CURVEDB, &curvedb);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "profile doesn't define curve database");
		return r;
	}

	r = sc_select_file(card, &curvedb->path, NULL);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "couldn't select curve database");
		goto out;
	}

	while ((r = sc_read_record(card, 0, (uint8_t *)buf,
	    sizeof(buf) - 1, SC_RECORD_NEXT)) > 0) {
		buf[127] = '\0';
		if (++ecd_id == 0) {
			r = SC_ERROR_INVALID_ARGUMENTS;
			sc_log(card->ctx, "ecd_id > UINT8_MAX");
			goto out;

		}
		if (strcmp(buf, entry) == 0) {
			r = 0; /* entry found; curve configured */
			goto out;
		}
	}

	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_SUCCESS)
		goto out;

	r = install_ecd(card, curvedb, param->named_curve, entry, ecd_id);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "failed to install ecd object");
		goto out;
	}

	r = sc_select_file(card, &curvedb->path, NULL);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "couldn't select curve database");
		goto out;
	}

	r = sc_append_record(card, (uint8_t *)entry, strlen(entry), 0);
	if (r < 0 || (size_t)r != strlen(entry))
		sc_log(card->ctx, "couldn't append record");

out:
	if (curvedb != NULL)
		sc_file_free(curvedb);

	return r;
}

static int
generate_ec_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_cardctl_cardos5_genkey_info	 args;
	struct sc_pkcs15_prkey_info		*keyinfo = obj->data;
	struct sc_context			*ctx = p15card->card->ctx;
	struct sc_file				*file = NULL;
	ec_keypair_t				 ec;
	uint8_t					 dummyQ[256];
	uint8_t					 dummyD[256];
	uint8_t					 payload_buf[256];
	uint8_t					 crt_buf[24];
	size_t					 keybits;
	buf_t					 crt;
	buf_t					 payload;
	int					 r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_EC)
		return SC_ERROR_NOT_SUPPORTED;

	keybits = keyinfo->modulus_length & ~7UL;
	if (keybits < 160 || keybits > 512) {
		sc_log(ctx, "unsupported key size %zu", keybits);
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, &file);
	if (r) {
		sc_log(ctx, "sc_select_file failed, r=%d", r);
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	sc_file_free(file);
	if (r) {
		sc_log(ctx, "sc_pkcs15init_authenticate failed, r=%d", r);
		return r;
	}

	lookup_ecd(profile, p15card->card, keyinfo);

	memset(dummyQ, 0xFF, sizeof(dummyQ));
	memset(dummyD, 0xFF, sizeof(dummyD));
	fill_in_dummy_ec_key(&ec, dummyQ, dummyD, keybits);

	r = put_ec_privkey(profile, p15card, keyinfo, &ec, 0);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put privkey, r=%d", r);
		return r;
	}

	/*
	 * CardOS 5 requires an additional public key stub for key generation.
	 */
	r = put_ec_pubkey(p15card, keyinfo, &ec);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put pubkey, r=%d", r);
		return r;
	}

	buf_init(&crt, crt_buf, sizeof(crt_buf));
	buf_init(&payload, payload_buf, sizeof(payload_buf));

	if (add_key_crt(keyinfo->key_reference, SC_ALGORITHM_EC, 0, 0, &crt) ||
	    asn1_put_tag(CRT_DO_DST, crt_buf, crt.bytes_used, &payload)) {
		sc_log(ctx, "asn1 error");
		return SC_ERROR_BUFFER_TOO_SMALL;
	}

	memset(&args, 0, sizeof(args));
	args.data = payload_buf;
	args.len = payload.bytes_used;
	r = sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_GENERATE_KEY, &args);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "key generation failed, r=%d", r);
		return r;
	}

	memset(pubkey, 0, sizeof(*pubkey));
	r = extract_ec_pubkey(p15card->card, keyinfo, pubkey);
	if (r != SC_SUCCESS) {
		free(pubkey->u.ec.ecpointQ.value);
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_context	*ctx = p15card->card->ctx;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		return generate_rsa_key(profile, p15card, obj, pubkey);
	case SC_PKCS15_TYPE_PRKEY_EC:
		return generate_ec_key(profile, p15card, obj, pubkey);
	default:
		sc_log(ctx, "unsupported key type %d", (int)obj->type);
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int
cardos5_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	struct sc_context	*ctx = p15card->card->ctx;
	sc_pkcs15_prkey_info_t	*keyinfo = obj->data;
	struct sc_file		*file = NULL;
	rsa_keypair_t		 rsa;
	int			 r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA ||
	    keyinfo->modulus_length > 4096) {
		sc_log(ctx, "only private rsa keys <= 4096-bit are supported");
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_select_file(p15card->card, &keyinfo->path, &file);
	if (r) {
		sc_log(ctx, "sc_select_file failed, r=%d", r);
		return r;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	sc_file_free(file);
	if (r) {
		sc_log(ctx, "sc_pkcs15init_authenticate failed, r=%d", r);
		return r;
	}

	memset(&rsa, 0x00, sizeof(rsa));
	rsa.bytes = keyinfo->modulus_length / 8;

	/* >= 2048-bit keys follow the Chinese Remainder Theorem format. */
	if (rsa.bytes > 256) {
		rsa.privkey.p.data = key->u.rsa.p.data;
		rsa.privkey.p.len = key->u.rsa.p.len;
		rsa.privkey.q.data = key->u.rsa.q.data;
		rsa.privkey.q.len = key->u.rsa.q.len;
		rsa.privkey.iqmp.data = key->u.rsa.iqmp.data;
		rsa.privkey.iqmp.len = key->u.rsa.iqmp.len;
		rsa.privkey.dmp1.data = key->u.rsa.dmp1.data;
		rsa.privkey.dmp1.len = key->u.rsa.dmp1.len;
		rsa.privkey.dmq1.data = key->u.rsa.dmq1.data;
		rsa.privkey.dmq1.len = key->u.rsa.dmq1.len;
	} else {
		rsa.privkey.modulus.data = key->u.rsa.modulus.data;
		rsa.privkey.modulus.len = key->u.rsa.modulus.len;
		rsa.privkey.d.data = key->u.rsa.d.data;
		rsa.privkey.d.len = key->u.rsa.d.len;
	}

	r = cardos_put_rsa_privkey(profile, p15card, keyinfo, &rsa, 1);
	if (r != SC_SUCCESS) {
		sc_log(ctx, "could not put privkey, r=%d", r);
		return r;
	}

	return SC_SUCCESS;
}

static int
cardos5_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	return sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_INIT_CARD, NULL);
}

static int
cardos5_delete_object(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
    struct sc_pkcs15_object *obj, const  struct sc_path *path)
{
	sc_file_t		*file = NULL;
	sc_pkcs15_prkey_info_t	*keyinfo = obj->data;
	struct sc_context	*ctx = p15card->card->ctx;
	int			 pin_id;
	int			 r;

	/* If we're removing a private key, explicitly invalidate it. */
	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY) {
		r = sc_pkcs15init_set_lifecycle(p15card->card,
		    SC_CARDCTRL_LIFECYCLE_ADMIN);
		if (r != SC_SUCCESS) {
			sc_log(ctx, "sc_pkcs15init_set_lifecycle: r=%d", r);
			return r;
		}
		r = sc_select_file(p15card->card, &keyinfo->path, NULL);
		if (r != SC_SUCCESS) {
			sc_log(ctx, "sc_select_file: r=%d", r);
			return r;
		}
		pin_id = sc_pkcs15init_get_pin_reference(p15card, profile,
		    SC_AC_SYMBOLIC, SC_PKCS15INIT_USER_PIN);
		if (pin_id >= 0) {
			r = sc_pkcs15init_verify_secret(profile, p15card, NULL,
			    SC_AC_CHV, pin_id);
			if (r < 0) {
				sc_log(ctx, "sc_pkcs15init_verify_secret: "
				    "r=%d", r);
				return r;
			}
		}
		r = sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_DELETE_KEY,
		    &keyinfo->key_reference);
		if (r != SC_SUCCESS) {
			sc_log(ctx, "sc_card_ctl SC_CARDCTL_CARDOS_DELETE_KEY:"
			    " r=%d", r);
			return r;
		}
	}

	/* Delete object from the PKCS15 file system. */
	if (path->len || path->aid.len) {
		r = sc_select_file(p15card->card, path, &file);
		if (r != SC_SUCCESS && r != SC_ERROR_FILE_NOT_FOUND) {
			sc_log(ctx, "sc_select_file: r=%d", r);
			return r;
		}
		if (r == SC_SUCCESS  && file->type != SC_FILE_TYPE_DF) {
			r = sc_pkcs15init_delete_by_path(profile, p15card,
			    path);
			if (r != SC_SUCCESS) {
				sc_file_free(file);
				sc_log(ctx, "sc_pkcs15init_delete_by_path: "
				    "r=%d", r);
				return r;
			}
		}
		sc_file_free(file);
	}

	return SC_SUCCESS;
}

static struct sc_pkcs15init_operations cardos5_ops, *cardos4_ops = NULL;

struct sc_pkcs15init_operations *
sc_pkcs15init_get_cardos5_ops(void)
{
	if (cardos4_ops == NULL)
		cardos4_ops = sc_pkcs15init_get_cardos_ops();

	cardos5_ops = *cardos4_ops;
	cardos5_ops.create_dir = cardos5_create_dir;
	cardos5_ops.create_pin = cardos5_create_pin;
	cardos5_ops.generate_key = cardos5_generate_key;
	cardos5_ops.store_key = cardos5_store_key;
	cardos5_ops.init_card = cardos5_init_card;
	cardos5_ops.delete_object = cardos5_delete_object;

	return &cardos5_ops;
}
