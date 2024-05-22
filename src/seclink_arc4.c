/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2017 Trusted Objects. All rights reserved.
 */

/**
 * @file seclink_arc4.c
 * @brief Secure Element ARC4 secure link implementation.
 */

#include <TO_stdint.h>
#include <TO_defs.h>
#include <TO.h>
#include <TO_endian.h>
#include <core.h>
#include <seclink.h>
#include <crc.h>

#ifdef ENABLE_SECLINK_ARC4

#define S_SIZE 256

/**
 * arc4ctx_t - ARC4 internal secret context
 */
typedef struct arc4ctx_s {
	uint8_t S[S_SIZE];
	uint8_t i, j;
} arc4ctx_t;

static arc4ctx_t arc4ctx;

static int arc4_load_keys(uint8_t *key)
{
	int ret;
	if (_seclink_load_keys_cb_p == NULL) {
		FPRINTF(stderr, "%s error: keys loading callback undefined\n",
				__func__);
		return TO_SECLINK_ERROR;
	}
	ret = _seclink_load_keys_cb_p((void *)key);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: unable to load keys\n", __func__);
		return ret;
	}
	return TO_OK;
}

static void arc4_encrypt(uint8_t *src, uint8_t *dst, uint16_t len)
{
	uint8_t tmp;
	uint16_t offset;
	for (offset = 0; offset < len; offset++) {
		arc4ctx.i += 1;
		arc4ctx.j += arc4ctx.S[arc4ctx.i];
		tmp = arc4ctx.S[arc4ctx.i];
		arc4ctx.S[arc4ctx.i] = arc4ctx.S[arc4ctx.j];
		arc4ctx.S[arc4ctx.j] = tmp;
		dst[offset] = arc4ctx.S[(uint8_t)(arc4ctx.S[arc4ctx.i]
				+ arc4ctx.S[arc4ctx.j])] ^ src[offset];
	}
}

static void arc4_decrypt(uint8_t *src, uint8_t *dst, uint16_t len)
{
	arc4_encrypt(src, dst, len);
}

static void arc4_init(const uint8_t *iv, const uint8_t *key)
{
	int i;
	uint8_t j, tmp;
	uint8_t iv_key[TO_ARC4_INITIALVECTOR_SIZE + TO_ARC4_KEY_SIZE];

	/* Prepare data */
	FPRINTF(stdout, "%s ARC4 initial vector: ", __func__);
	HEX_DISP(iv, TO_ARC4_INITIALVECTOR_SIZE);
	FPRINTF(stdout, "%s ARC4 key: ", __func__);
	HEX_DISP(key, TO_ARC4_KEY_SIZE);
	secure_memcpy(iv_key, iv, TO_ARC4_INITIALVECTOR_SIZE);
	secure_memcpy(iv_key + TO_ARC4_INITIALVECTOR_SIZE, key, TO_ARC4_KEY_SIZE);

	/* ARC4 init */
	for (i = 0; i < S_SIZE; i++)
		arc4ctx.S[i] = i;
	j = 0;
	for (i = 0; i < S_SIZE; i++) {
		j += arc4ctx.S[i] + iv_key[i % sizeof(iv_key)];
		tmp = arc4ctx.S[i];
		arc4ctx.S[i] = arc4ctx.S[j];
		arc4ctx.S[j] = tmp;
	}
	arc4ctx.i = 0;
	arc4ctx.j = 0;

	/* Discard first 256 bytes */
	for (i = 0; i < 256; i++) {
		arc4_encrypt(&tmp, &tmp, 1);
	}
}

int TO_seclink_init(void)
{
	int ret;
	uint8_t io_buffer[TO_RSPHEAD_SIZE + TO_ARC4_INITIALVECTOR_SIZE];
	uint16_t cmd, *len;
	uint8_t key[TO_ARC4_KEY_SIZE];

	/* Load key */
	ret = arc4_load_keys(key);
	if (ret != TO_OK)
		return ret;

	/* Get IV from Secure Element */
	cmd = htobe16(TOCMD_SECLINK_ARC4_GET_IV);
	io_buffer[0] = cmd & 0x00FF;
	io_buffer[1] = cmd >> 8;
	io_buffer[2] = 0;
	io_buffer[3] = 0;
	io_buffer[4] = 0;
	ret = TO_write(io_buffer, TO_CMDHEAD_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: can't request ARC4 IV\n", __func__);
		return ret;
	}
	ret = TO_read(io_buffer,
			TO_RSPHEAD_SIZE + TO_ARC4_INITIALVECTOR_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: can't read ARC4 IV\n", __func__);
		return ret;
	}
	len = (uint16_t*)io_buffer;
	*len = be16toh(*len);
	if (*len != TO_ARC4_INITIALVECTOR_SIZE) {
		FPRINTF(stderr, "%s error: bad IV len %hu\n", __func__, *len);
		return TO_SECLINK_ERROR;
	}
	if (io_buffer[2] != TORSP_SUCCESS) {
		FPRINTF(stderr, "%s error: Secure Element returned %02X\n",
				__func__, io_buffer[2]);
		return TO_SECLINK_ERROR;
	}

	/* Use this IV to initialize Secure Link */
	arc4_init(io_buffer + TO_RSPHEAD_SIZE, key);

	return TO_OK;
}

int TO_seclink_renew_keys(void)
{
	int ret;
	uint8_t io_buffer[TO_RSPHEAD_SIZE + TO_ARC4_INITIALVECTOR_SIZE
		+ TO_ARC4_KEY_SIZE + TO_CRC_SIZE];
	uint16_t cmd, len, crc, ref_crc;
	uint8_t key[TO_ARC4_KEY_SIZE];

	/* Load key */
	ret = arc4_load_keys(key);
	if (ret != TO_OK)
		return ret;

	/* Request key renewal information from Secure Element */
	FPRINTF(stdout, "Renew ARC4 key\n");
	cmd = htobe16(TOCMD_SECLINK_ARC4_GET_NEW_KEY);
	io_buffer[0] = cmd & 0x00FF;
	io_buffer[1] = cmd >> 8;
	io_buffer[2] = 0;
	io_buffer[3] = 0;
	io_buffer[4] = 0;
	ret = TO_write(io_buffer, TO_CMDHEAD_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: can't get new ARC4 key\n", __func__);
		return ret;
	}
	ret = TO_read(io_buffer, TO_RSPHEAD_SIZE + TO_ARC4_INITIALVECTOR_SIZE
			+ TO_ARC4_KEY_SIZE + TO_CRC_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: can't read renewed ARC4 key\n",
				__func__);
		return ret;
	}
	len = be16toh(*((uint16_t*)io_buffer));
	if (len != TO_ARC4_INITIALVECTOR_SIZE + TO_ARC4_KEY_SIZE
			+ TO_CRC_SIZE) {
		FPRINTF(stderr, "%s error: bad key renewal response len %hu\n",
				__func__, len);
		return TO_SECLINK_ERROR;
	}
	if (io_buffer[2] != TORSP_SUCCESS) {
		FPRINTF(stderr, "%s error: Secure Element returned %02X\n",
				__func__, io_buffer[2]);
		return TO_SECLINK_ERROR;
	}

	/* Extract encrypted new key by using deprecated key and given IV */
	arc4_init(io_buffer + TO_RSPHEAD_SIZE, key);
	arc4_decrypt(io_buffer + TO_RSPHEAD_SIZE + TO_ARC4_INITIALVECTOR_SIZE,
			io_buffer, TO_ARC4_KEY_SIZE + TO_CRC_SIZE);
	FPRINTF(stdout, "New ARC4 key: ");
	HEX_DISP(io_buffer, TO_ARC4_KEY_SIZE);
	crc = be16toh(*((uint16_t*)(io_buffer + TO_ARC4_KEY_SIZE)));
	FPRINTF(stdout, "Key CRC: 0x%04X\n", crc);
	/* Check new key CRC */
	ref_crc = crc16_ccitt_29b1(CRC16_SEED, io_buffer, TO_ARC4_KEY_SIZE, 1);
	if (crc != ref_crc) {
		FPRINTF(stderr, "%s error: bad key CRC, expected 0x%04X\n",
				__func__, ref_crc);
		return TO_SECLINK_ERROR;
	}

	/* Use the new key */
	if (_seclink_store_keys_cb_p == NULL) {
		FPRINTF(stderr, "%s error: keys storage callback undefined\n",
				__func__);
		return TO_ERROR;
	}
	ret = _seclink_store_keys_cb_p(io_buffer);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error storing new key\n", __func__);
		return ret;
	}
	TO_seclink_init();

	return TO_OK;
}

int TO_seclink_secure(uint8_t *io_buffer, uint16_t len)
{
	uint16_t cmd, _len, crc;
	int i;

	/* Make place for ARC4 secure link headers */
	for (i = len - 1; i >= 0; i--)
		io_buffer[i + TO_CMDHEAD_SIZE] = io_buffer[i];
	cmd = htobe16(TOCMD_SECLINK_ARC4);
	_len = htobe16(len + TO_CRC_SIZE);
	io_buffer[0] = cmd & 0x00FF;
	io_buffer[1] = cmd >> 8;
	io_buffer[2] = _len & 0x00FF;
	io_buffer[3] = _len >> 8;
	io_buffer[4] = 0;

	/* Compute encapsulated command CRC */
	crc = crc16_ccitt_29b1(CRC16_SEED, io_buffer + TO_CMDHEAD_SIZE, len, 1);
	*((uint16_t*)(io_buffer + TO_CMDHEAD_SIZE + len)) = htobe16(crc);

	/* Encrypt encapsulated command and its CRC */
	arc4_encrypt(io_buffer + TO_CMDHEAD_SIZE,
			io_buffer + TO_CMDHEAD_SIZE, len + TO_CRC_SIZE);
	FPRINTF(stdout, "%s output: ", __func__);
	HEX_DISP(io_buffer, len + TO_CMDHEAD_SIZE + TO_CRC_SIZE);

	return TO_OK;
}

int TO_seclink_unsecure(uint8_t *io_buffer)
{
	uint16_t len, crc, ref_crc;
	uint8_t st;

	/* Check headers */
	len = be16toh(io_buffer[0] | io_buffer[1] << 8);
	st = io_buffer[2];
	if (st != TORSP_SUCCESS) {
		return TO_SECLINK_ERROR | st;
	}
	if (len < TO_RSPHEAD_SIZE)
		return TO_INVALID_RESPONSE_LENGTH;

	/* Decrypt encapsulated response and CRC */
	FPRINTF(stdout, "%s input: ", __func__);
	HEX_DISP(io_buffer, len + TO_RSPHEAD_SIZE);
	arc4_decrypt(io_buffer + TO_RSPHEAD_SIZE, io_buffer, len);

	/* Check CRC of encapsulated response */
	crc = be16toh(*((uint16_t*)(io_buffer + len - TO_CRC_SIZE)));
	ref_crc = crc16_ccitt_29b1(CRC16_SEED, io_buffer, len - TO_CRC_SIZE, 1);
	if (crc != ref_crc) {
		FPRINTF(stderr, "%s error: bad CRC 0x%04X, expected 0x%04X\n",
				__func__, crc, ref_crc);
		return TO_SECLINK_ERROR;
	}

	return TO_OK;
}

uint16_t TO_seclink_compute_cmd_size(uint16_t encaps_len)
{
	return encaps_len + TO_CMDHEAD_SIZE + TO_CRC_SIZE;
}

uint16_t TO_seclink_compute_rsp_size(uint16_t encaps_len)
{
	return encaps_len + TO_RSPHEAD_SIZE + TO_CRC_SIZE;
}

#endif // ENABLE_SECLINK_ARC4
