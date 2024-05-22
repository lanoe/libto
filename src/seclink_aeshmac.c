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
 * @file seclink_aeshmac.c
 * @brief Secure Element AES/HMAC secure link implementation.
 *
 * Supports:
 * - AES128-CBC
 * - HMAC-SHA256
 */

#include <TO_stdint.h>
#include <TO_defs.h>
#include <TO.h>
#include <TO_endian.h>
#include <core.h>
#include <seclink.h>

#ifdef ENABLE_SECLINK_AESHMAC

#include <tinycrypt/aes.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>

#if TC_AES_BLOCK_SIZE != TO_AES_BLOCK_SIZE
#error "Tinycrypt and Secure Element AES blocks sizes differ"
#endif
#if TC_SHA256_DIGEST_SIZE != TO_HMAC_SIZE
#error "Tinycrypt and Secure Element HMAC sizes differ"
#endif

#define GET_IV_RSP_SIZE (TO_RSPHEAD_SIZE + \
		TO_INITIALVECTOR_SIZE + TO_HMAC_SIZE)

/**
 * aeshmacctx_t - AES/HMAC context
 * @iv: Initial vector
 */
typedef struct aeshmacctx_s {
	uint8_t iv[TO_INITIALVECTOR_SIZE];
} aeshmacctx_t;

static aeshmacctx_t aeshmacctx;

/**
 * @brief: Load secure link AES and HMAC keys
 * @param aes_key Buffer for AES key, ignored if NULL
 * @param hmac_key Buffer for HMAC key, ignored if NULL
 *
 * @return TO_OK on success
 */
static int aeshmac_load_keys(uint8_t *aes_key, uint8_t *hmac_key)
{
	int ret;
	uint8_t keys[TO_AES_KEYSIZE + TO_HMAC_KEYSIZE];
	if (_seclink_load_keys_cb_p == NULL) {
		FPRINTF(stderr, "%s error: keys loading callback undefined\n",
				__func__);
		return TO_SECLINK_ERROR;
	}
	ret = _seclink_load_keys_cb_p((void *)keys);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: unable to load keys\n", __func__);
		return ret;
	}
	if (aes_key != NULL)
		secure_memcpy(aes_key, keys, TO_AES_KEYSIZE);
	if (hmac_key != NULL)
		secure_memcpy(hmac_key, keys + TO_AES_KEYSIZE, TO_HMAC_KEYSIZE);
	return TO_OK;
}

/**
 * compute_aes_cbc_padding() - Compute AES CBC padding length/value
 * @len: Data length to encrypt
 *
 * Padding has to be added because encrypted data length must be a multiple of
 * AES block size.
 * Padded bytes count and padded bytes value must be equal to the value
 * returned by this function.
 *
 * Return: padding lenght/value
 */
static uint16_t compute_aes_cbc_padding(uint16_t len)
{
	return TO_AES_BLOCK_SIZE - (len % TO_AES_BLOCK_SIZE);
}

/**
 * aes_cbc_encrypt() - AES-CBC encryption
 * @out: Cryptogram
 * @in: Clear text
 * @len: Cryptogram / Clear text length
 * @iv: Initial vector (updated on return)
 * @sched: Tinycrypt AES context
 *
 * Clear text length must be multiple of AES block size. Padding has to be
 * appended to clear text. Padded bytes count and padded bytes value must be
 * equal to the value returned by compute_aes_cbc_padding().  It is allowed to
 * have the same buffer for in and out.
 *
 * Return: TO_OK on success
 */
static int aes_cbc_encrypt(uint8_t *out, const uint8_t *in,
		uint16_t len, uint8_t *iv, const TCAesKeySched_t ctx)
{
	int ret, i, j;
	uint8_t aes_block[TO_AES_BLOCK_SIZE];

	if (len % TO_AES_BLOCK_SIZE) {
		FPRINTF(stderr, "%s invalid length %d\n", __func__, len);
		return TO_ERROR;
	}

	secure_memcpy(aes_block, iv, TO_AES_BLOCK_SIZE);
	j = 0;
	for (i = 0; i < len; i++) {
		aes_block[j] ^= in[j];
		j++;
		if (j == TO_AES_BLOCK_SIZE) {
			ret = tc_aes_encrypt(aes_block, aes_block, ctx);
			if (ret != TC_CRYPTO_SUCCESS) {
				FPRINTF(stderr, "%s encrypt error\n", __func__);
				return TO_ERROR;
			}
			secure_memcpy(out, aes_block, TO_AES_BLOCK_SIZE);
			j = 0;
			in += TC_AES_BLOCK_SIZE;
			out += TC_AES_BLOCK_SIZE;
		}
	}
	secure_memcpy(iv, aes_block, TO_AES_BLOCK_SIZE);

	return TO_OK;
}

/**
 * aes_cbc_decrypt() - AES-CBC encryption
 * @out: Clear text
 * @in: Cryptogram
 * @len: Cryptogram / Clear text length
 * @iv: Initial vector (updated on return)
 * @sched: Tinycrypt AES context
 *
 * Padding is present at the end of clear text, each byte filled with padding
 * value.
 * It is allowed to have the same buffer for in and out.
 *
 * Return: TO_OK on success
 */
static int aes_cbc_decrypt(uint8_t *out, const uint8_t *in,
		uint16_t len, uint8_t *iv, const TCAesKeySched_t ctx)
{
	int ret, i, j;
	uint8_t aes_block[TO_AES_BLOCK_SIZE];
	uint8_t tmp;

	if (len % TO_AES_BLOCK_SIZE) {
		FPRINTF(stderr, "%s invalid length %d\n", __func__, len);
		return TO_ERROR;
	}

	j = TO_AES_BLOCK_SIZE;
	for (i = 0; i < len; i++) {
		if (j == TO_AES_BLOCK_SIZE) {
			ret = tc_aes_decrypt(aes_block, in, ctx);
			if (ret != TC_CRYPTO_SUCCESS) {
				FPRINTF(stderr, "%s decrypt error\n", __func__);
				return TO_ERROR;
			}
			in += TO_AES_BLOCK_SIZE;
			j = 0;
		}
		tmp = *(in + j - TO_AES_BLOCK_SIZE);
		*out = aes_block[j] ^ iv[j];
		iv[j] = tmp; /* prepare IV for the next block */
		out++;
		j++;
	}

	return TO_OK;
}

/**
 * compute_hmac() - Compute HMAC
 * @hmac: Computed HMAC
 * @data: Data to compute HMAC on
 * @len: Data length
 * @key: HMAC key
 *
 * Return: TO_OK on success
 */
static int compute_hmac(uint8_t *hmac, const uint8_t *data, uint16_t len,
		uint8_t *key)
{
	int ret;
	struct tc_hmac_state_struct hmac_st;

	secure_memset(&hmac_st, 0x00, sizeof(hmac_st));
	ret = tc_hmac_set_key(&hmac_st, key, TO_HMAC_KEYSIZE);
	if (ret != TC_CRYPTO_SUCCESS) {
		FPRINTF(stderr, "%s unable to set HMAC key\n", __func__);
		return TO_ERROR;
	}
	ret = tc_hmac_init(&hmac_st);
	if (ret != TC_CRYPTO_SUCCESS) {
		FPRINTF(stderr, "%s error on HMAC init\n", __func__);
		return TO_ERROR;
	}
	tc_hmac_update(&hmac_st, data, len);
	if (ret != TC_CRYPTO_SUCCESS) {
		FPRINTF(stderr, "%s error on HMAC update\n", __func__);
		return TO_ERROR;
	}
	tc_hmac_final(hmac, TO_HMAC_SIZE, &hmac_st);
	if (ret != TC_CRYPTO_SUCCESS) {
		FPRINTF(stderr, "%s error on HMAC final\n", __func__);
		return TO_ERROR;
	}
	return TO_OK;
}

uint16_t TO_seclink_compute_cmd_size(uint16_t encaps_len)
{
	uint16_t padding = compute_aes_cbc_padding(encaps_len);
	return TO_CMDHEAD_SIZE + encaps_len + padding + TO_HMAC_SIZE;
}

uint16_t TO_seclink_compute_rsp_size(uint16_t encaps_len)
{
	uint16_t padding = compute_aes_cbc_padding(encaps_len);
	return TO_RSPHEAD_SIZE + encaps_len + padding + TO_HMAC_SIZE;
}

/**
 * seclink_get_iv() - Load initial vector from SE into the context
 *
 * @return: TO_OK on success, else
 * TO_SECLINK_ERROR: HMAC verification failed
 * TO_INVALID_RESPONSE_LENGTH: bad response length from SE
 * or another error code.
 */
static int seclink_get_iv(void)
{
	int ret;
	uint8_t io_buffer[GET_IV_RSP_SIZE];
	uint16_t cmd, *len;
	uint8_t hmac[TO_HMAC_SIZE];
	unsigned int i;
	uint8_t hmac_key[TO_HMAC_KEYSIZE];

	/* Load keys */
	ret = aeshmac_load_keys(NULL, hmac_key);
	if (ret != TO_OK)
		return TO_ERROR;

	/* Get IV from TO, check size and status */
	cmd = htobe16(TOCMD_SECLINK_AESHMAC_GET_IV);
	io_buffer[0] = cmd & 0x00FF;
	io_buffer[1] = cmd >> 8;
	io_buffer[2] = 0;
	io_buffer[3] = 0;
	io_buffer[4] = 0;
	ret = TO_write(io_buffer, TO_CMDHEAD_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error requesting AES/HMAC IV\n", __func__);
		return ret;
	}
	ret = TO_read(io_buffer, GET_IV_RSP_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error reading AES/HMAC IV\n", __func__);
		return ret;
	}
	len = (uint16_t*)io_buffer;
	*len = be16toh(*len);
	if (*len != TO_INITIALVECTOR_SIZE + TO_HMAC_SIZE) {
		FPRINTF(stderr, "%s bad response len %hu\n", __func__, *len);
		return TO_INVALID_RESPONSE_LENGTH;
	}
	if (io_buffer[2] != TORSP_SUCCESS) {
		FPRINTF(stderr, "%s SE error %02X\n", __func__, io_buffer[2]);
		return TO_ERROR | io_buffer[2];
	}

	/* Verify HMAC */
	ret = compute_hmac(hmac, io_buffer + TO_RSPHEAD_SIZE,
			TO_INITIALVECTOR_SIZE, hmac_key);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error computing HMAC\n", __func__);
		return TO_ERROR;
	}
	if (secure_memcmp(hmac, io_buffer + TO_RSPHEAD_SIZE +
				TO_INITIALVECTOR_SIZE, TO_HMAC_SIZE)) {
		FPRINTF(stderr, "%s HMAC doesn't match\n", __func__);
		return TO_SECLINK_ERROR;
	}

	/* Keep initial vector in context */
	for (i = 0; i < TO_INITIALVECTOR_SIZE; i++)
		aeshmacctx.iv[i] = io_buffer[TO_RSPHEAD_SIZE + i];

	FPRINTF(stdout, "%s AES/HMAC initial vector: ", __func__);
	HEX_DISP(aeshmacctx.iv, TO_INITIALVECTOR_SIZE);
	return TO_OK;
}

int TO_seclink_init(void)
{
	int ret;

	ret = seclink_get_iv();
	if (ret == TO_SECLINK_ERROR) {
		FPRINTF(stdout, "%s check if there is new keys...\n", __func__);
		ret = TO_seclink_renew_keys();
		if (ret != TO_OK)
			return TO_SECLINK_ERROR;
	} else if (ret != TO_OK) {
		return TO_SECLINK_ERROR;
	}

	return TO_OK;
}

int TO_seclink_renew_keys(void)
{
	int ret;
	uint8_t io_buffer[TO_RSPHEAD_SIZE + TO_INITIALVECTOR_SIZE
		+ TO_AES_KEYSIZE + TO_HMAC_KEYSIZE + TO_HMAC_SIZE];
	uint16_t cmd, len;
	uint8_t hmac[TO_HMAC_SIZE];
	struct tc_aes_key_sched_struct aes_st;
	uint8_t old_aes_key[TO_AES_KEYSIZE], old_hmac_key[TO_HMAC_KEYSIZE];
	uint8_t keys[TO_AES_KEYSIZE + TO_HMAC_KEYSIZE];

	/* Load keys */
	ret = aeshmac_load_keys(old_aes_key, old_hmac_key);
	if (ret != TO_OK)
		return ret;

	/* Request key renewal information from Secure Element */
	FPRINTF(stdout, "Renew secure link AES/HMAC key\n");
	cmd = htobe16(TOCMD_SECLINK_AESHMAC_GET_NEW_KEYS);
	io_buffer[0] = cmd & 0x00FF;
	io_buffer[1] = cmd >> 8;
	io_buffer[2] = 0;
	io_buffer[3] = 0;
	io_buffer[4] = 0;
	ret = TO_write(io_buffer, TO_CMDHEAD_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: can't get new AES/HMAC keys\n",
				__func__);
		return ret;
	}
	ret = TO_read(io_buffer, TO_RSPHEAD_SIZE + TO_INITIALVECTOR_SIZE
			+ TO_AES_KEYSIZE + TO_HMAC_KEYSIZE + TO_HMAC_SIZE);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: can't read renewed AES/HMAC keys\n",
				__func__);
		return ret;
	}
	len = be16toh(*((uint16_t*)io_buffer));
	if (len != TO_INITIALVECTOR_SIZE + TO_AES_KEYSIZE + TO_HMAC_KEYSIZE
			+ TO_HMAC_SIZE) {
		FPRINTF(stderr, "%s error: bad key renewal response len %hu\n",
				__func__, len);
		return TO_SECLINK_ERROR;
	}
	if (io_buffer[2] != TORSP_SUCCESS) {
		FPRINTF(stderr, "%s error: Secure Element returned %02X\n",
				__func__, io_buffer[2]);
		return TO_SECLINK_ERROR;
	}

	/* Verify HMAC */
	ret = compute_hmac(hmac,
			io_buffer + TO_RSPHEAD_SIZE + TO_INITIALVECTOR_SIZE,
			TO_AES_KEYSIZE + TO_HMAC_KEYSIZE, old_hmac_key);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error computing HMAC\n", __func__);
		return TO_SECLINK_ERROR;
	}
	if (secure_memcmp(hmac, io_buffer + TO_RSPHEAD_SIZE +
				TO_INITIALVECTOR_SIZE + TO_AES_KEYSIZE
				+ TO_HMAC_KEYSIZE, TO_HMAC_SIZE)) {
		FPRINTF(stderr, "%s HMAC doesn't match\n", __func__);
		return TO_SECLINK_ERROR;
	}

	/* Extract encrypted new keys by using deprecated keys and given IV */
	ret = tc_aes128_set_decrypt_key(&aes_st, old_aes_key);
	if (ret != TC_CRYPTO_SUCCESS) {
		FPRINTF(stderr, "%s unable to set AES key\n", __func__);
		return TO_SECLINK_ERROR;
	}
	ret = aes_cbc_decrypt(keys,
			io_buffer + TO_RSPHEAD_SIZE + TO_INITIALVECTOR_SIZE,
			TO_AES_KEYSIZE + TO_HMAC_KEYSIZE,
			io_buffer + TO_RSPHEAD_SIZE, &aes_st);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s unable to decrypt new keys\n", __func__);
		return TO_SECLINK_ERROR;
	}
	FPRINTF(stdout, "New AES key: ");
	HEX_DISP(keys, TO_AES_KEYSIZE);
	FPRINTF(stdout, "New HMAC key: ");
	HEX_DISP(keys + TO_AES_KEYSIZE, TO_HMAC_KEYSIZE);

	/* Use the new key */
	if (_seclink_store_keys_cb_p == NULL) {
		FPRINTF(stderr, "%s error: keys storage callback undefined\n",
				__func__);
		return TO_ERROR;
	}
	ret = _seclink_store_keys_cb_p(keys);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error storing new key\n", __func__);
		return ret;
	}
	ret = seclink_get_iv();
	if (ret != TO_OK)
		return ret;

	return TO_OK;
}

int TO_seclink_secure(uint8_t *io_buffer, uint16_t len)
{
	int ret;
	uint16_t cmd;
	uint16_t padding;
	uint16_t _len;
	int i;
	struct tc_aes_key_sched_struct aes_st;
	uint8_t aes_key[TO_AES_KEYSIZE], hmac_key[TO_HMAC_KEYSIZE];

	/* Load keys */
	ret = aeshmac_load_keys(aes_key, hmac_key);
	if (ret != TO_OK)
		return TO_SECLINK_ERROR;

	/* Make place for secure link headers */
	for (i = len - 1; i >= 0; i--)
		io_buffer[i + TO_CMDHEAD_SIZE] = io_buffer[i];

	/* Add padding to encapsulated command */
	padding = compute_aes_cbc_padding(len);
	for (i = 0; i < padding; i++)
		io_buffer[TO_CMDHEAD_SIZE + len + i] = padding;
	len += padding;

	/* Prepare secure link headers */
	cmd = htobe16(TOCMD_SECLINK_AESHMAC);
	_len = htobe16(len + TO_HMAC_SIZE);
	io_buffer[0] = cmd & 0x00FF;
	io_buffer[1] = cmd >> 8;
	io_buffer[2] = _len & 0x00FF;
	io_buffer[3] = _len >> 8;
	io_buffer[4] = 0;

	/* Encrypt encapsulated command */
	ret = tc_aes128_set_encrypt_key(&aes_st, aes_key);
	if (ret != TC_CRYPTO_SUCCESS) {
		FPRINTF(stderr, "%s unable to set AES key\n", __func__);
		return TO_SECLINK_ERROR;
	}
	ret = aes_cbc_encrypt(io_buffer + TO_CMDHEAD_SIZE,
			io_buffer + TO_CMDHEAD_SIZE, len,
			aeshmacctx.iv, &aes_st);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s command encryption error\n", __func__);
		return TO_SECLINK_ERROR;
	}

	/* Compute HMAC */
	ret = compute_hmac(io_buffer + TO_CMDHEAD_SIZE + len,
			io_buffer + TO_CMDHEAD_SIZE, len, hmac_key);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error computing HMAC\n", __func__);
		return TO_SECLINK_ERROR;
	}

	FPRINTF(stdout, "%s output: ", __func__);
	HEX_DISP(io_buffer, TO_CMDHEAD_SIZE + len + TO_HMAC_SIZE);
	return TO_OK;
}

int TO_seclink_unsecure(uint8_t *io_buffer)
{
	int ret;
	uint16_t len;
	uint8_t st;
	uint8_t hmac[TO_HMAC_SIZE];
	struct tc_aes_key_sched_struct aes_st;
	uint8_t aes_key[TO_AES_KEYSIZE], hmac_key[TO_HMAC_KEYSIZE];

	/* Load keys */
	ret = aeshmac_load_keys(aes_key, hmac_key);
	if (ret != TO_OK)
		return TO_SECLINK_ERROR;

	/* Extract headers */
	len = be16toh(io_buffer[0] | io_buffer[1] << 8);
	st = io_buffer[2];
	if (st != TORSP_SUCCESS) {
		FPRINTF(stdout, "%s seclink error %X\n", __func__, st);
		return TO_SECLINK_ERROR | st;
	}
	if (len < TO_RSPHEAD_SIZE)
		return TO_INVALID_RESPONSE_LENGTH;
	FPRINTF(stdout, "%s input: ", __func__);
	HEX_DISP(io_buffer, len + TO_RSPHEAD_SIZE);

	/* Verify HMAC */
	ret = compute_hmac(hmac, io_buffer + TO_RSPHEAD_SIZE,
			len - TO_HMAC_SIZE, hmac_key);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error computing HMAC\n", __func__);
		return TO_SECLINK_ERROR;
	}
	if (secure_memcmp(hmac, io_buffer + TO_RSPHEAD_SIZE +
				len - TO_HMAC_SIZE, TO_HMAC_SIZE)) {
		FPRINTF(stderr, "%s HMAC doesn't match\n", __func__);
		return TO_SECLINK_ERROR;
	}

	/* Decrypt encapsulated command */
	ret = tc_aes128_set_decrypt_key(&aes_st, aes_key);
	if (ret != TC_CRYPTO_SUCCESS) {
		FPRINTF(stderr, "%s unable to set AES key\n", __func__);
		return TO_SECLINK_ERROR;
	}
	ret = aes_cbc_decrypt(io_buffer, io_buffer + TO_RSPHEAD_SIZE,
			len - TO_HMAC_SIZE, aeshmacctx.iv, &aes_st);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s command decryption error\n", __func__);
		return TO_SECLINK_ERROR;
	}

	return TO_OK;
}

#endif // ENABLE_SECLINK_AESHMAC
