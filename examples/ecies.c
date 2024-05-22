/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2018 Trusted Objects. All rights reserved.
 */

/**
 * @file ecies.c
 * @brief Simple client/server ECIES example using Trusted Objects library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <TO.h>
#include <TO_endian.h>

#include "ecies.h"

#define LOCAL_ECC_KEY_INDEX 0
#define REMOTE_ECC_KEY_INDEX 0

#define USE_AUTH

#define HELLO_MSG "Hello!"

#if !defined(TO_ECIES_CLIENT) && !defined(TO_ECIES_SERVER)
#error "You must define device type ('TO_ECIES_CLIENT' or 'TO_ECIES_SERVER')"
#endif

#ifdef USE_AUTH
static uint8_t buf[TO_MAXSIZE];

typedef enum data_type_e {
	ECIES_CHALLENGE,
	ECIES_CERTIFICATE_AND_SIGN,
	ECIES_KEY,
	ECIES_CYPHERED_DATA
} data_type_t;

typedef enum step_e {
	ECIES_AUTH_INIT,
	ECIES_AUTH_PEER,
	ECIES_AUTH_LOCAL,
	ECIES_KEY_PEER,
	ECIES_KEY_LOCAL,
	ECIES_DONE
} step_t;

static int auth_local(void)
{
	int ret;
	payload_t *payload = (payload_t*)buf;
	uint16_t len;

	/* Receive peer challenge */
	if ((ret = recv_data((uint8_t*)payload, sizeof(buf), &len)) != 0) {
		fprintf(stderr, "recv_data() failed\n");
		return ret;
	}
	ASSERT(payload->data_type == ECIES_CHALLENGE);
	ASSERT(DATA_SIZE(payload) == TO_CHALLENGE_SIZE);

	/* Sign peer challenge and return certificate */
	if ((ret = TO_get_certificate_and_sign(0, TO_CERTIFICATE_SHORT,
					payload->data, TO_CHALLENGE_SIZE, payload->data,
					payload->data + sizeof(TO_cert_short_t)))
			!= TORSP_SUCCESS) {
		fprintf(stderr, "TO_get_certificate_and_sign() failed\n");
		return -1;
	}
	payload->data_type = ECIES_CERTIFICATE_AND_SIGN;
	payload->data_size = htobe16(sizeof(TO_cert_short_t) + TO_SIGNATURE_SIZE);
	if ((ret = send_data((uint8_t*)payload, PAYLOAD_SIZE(payload))) != 0) {
		fprintf(stderr, "send_data() failed\n");
		return ret;
	}

	return 0;
}

static int auth_peer(void)
{
	int ret;
	payload_t *payload = (payload_t*)buf;
	uint16_t len;

	/* Send local challenge */
	if ((ret = TO_get_challenge_and_store(payload->data)) != TORSP_SUCCESS) {
		fprintf(stderr, "TO_get_challenge_and_store() failed\n");
		return -1;
	}
	payload->data_type = ECIES_CHALLENGE;
	payload->data_size = htobe16(TO_CHALLENGE_SIZE);
	if ((ret = send_data((uint8_t*)payload, PAYLOAD_SIZE(payload))) != 0) {
		fprintf(stderr, "send_data() failed\n");
		return ret;
	}

	/* Verify peer certificate and signature */
	if ((ret = recv_data((uint8_t*)payload, sizeof(buf), &len)) != 0) {
		fprintf(stderr, "recv_data() failed\n");
		return ret;
	}
	ASSERT(payload->data_type == ECIES_CERTIFICATE_AND_SIGN);
	ASSERT(DATA_SIZE(payload) == sizeof(TO_cert_short_t) + TO_SIGNATURE_SIZE);
	if ((ret = TO_verify_certificate_and_store(0, TO_CERTIFICATE_SHORT,
					payload->data)) != TORSP_SUCCESS) {
		fprintf(stderr, "TO_verify_certificate_and_store() failed\n");
		return -1;
	}
	if ((ret = TO_verify_challenge_signature(payload->data +
					sizeof(TO_cert_short_t))) != TORSP_SUCCESS) {
		fprintf(stderr, "TO_verify_challenge_signature() failed\n");
		return -1;
	}

	return 0;
}

static int auth_key_local(void)
{
	int ret;
	payload_t *payload = (payload_t*)buf;

	/* Renew ephemeral key pair */
	if ((ret = TO_renew_ecc_keys(LOCAL_ECC_KEY_INDEX)) != TORSP_SUCCESS) {
		fprintf(stderr, "TO_renew_ecc_keys() failed\n");
		return -1;
	}

	/* Send signed public key */
	if ((ret = TO_get_public_key(LOCAL_ECC_KEY_INDEX, payload->data,
					payload->data + TO_ECC_PUB_KEYSIZE)) != TORSP_SUCCESS) {
		fprintf(stderr, "TO_get_public_key() failed\n");
		return -1;
	}
	payload->data_type = ECIES_KEY;
	payload->data_size = htobe16(TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE);
	if ((ret = send_data((uint8_t*)payload, PAYLOAD_SIZE(payload))) != 0) {
		fprintf(stderr, "send_data() failed\n");
		return ret;
	}

	return 0;
}

static int auth_key_peer(void)
{
	int ret;
	uint16_t len;
	payload_t *payload = (payload_t*)buf;

	/* Receive peer key and signature */
	if ((ret = recv_data((uint8_t*)payload, sizeof(buf), &len)) != 0) {
		fprintf(stderr, "recv_data() failed\n");
		return ret;
	}
	ASSERT(payload->data_type == ECIES_KEY);
	ASSERT(DATA_SIZE(payload) == TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE);

	/* Verify peer key */
	if ((ret = TO_set_remote_public_key(REMOTE_ECC_KEY_INDEX, payload->data,
					payload->data + TO_ECC_PUB_KEYSIZE)) != TORSP_SUCCESS) {
		fprintf(stderr, "TO_set_remote_public_key() failed\n");
		return -1;
	}

	return 0;
}

static int auth(void)
{
	int ret;
	static step_t step = ECIES_AUTH_INIT;

	if (step == ECIES_DONE) {
		return 0;
	}

#ifdef TO_ECIES_CLIENT
	step = ECIES_AUTH_PEER;
#else
	step = ECIES_AUTH_LOCAL;
#endif

	while (step != ECIES_DONE) {

		switch (step) {

			/* Authentication of local device to remote device */
			case ECIES_AUTH_LOCAL:
				if ((ret = auth_local()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_KEY_PEER;
#else
				step = ECIES_AUTH_PEER;
#endif
				break;

			/* Authentication of remote device to local device */
			case ECIES_AUTH_PEER:
				if ((ret = auth_peer()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_AUTH_LOCAL;
#else
				step = ECIES_KEY_LOCAL;
#endif
				break;

			/* Exchange of remote device ephemeral public key */
			case ECIES_KEY_PEER:
				if ((ret = auth_key_peer()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_KEY_LOCAL;
#else
				step = ECIES_DONE;
#endif
				break;

			/* Exchange of local device ephemeral public key */
			case ECIES_KEY_LOCAL:
				if ((ret = auth_key_local()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_DONE;
#else
				step = ECIES_KEY_PEER;
#endif
				break;

			default:
				fprintf(stderr, "Un-expexted step %d\n", step);
				return -1;
		}
	}

	/* Calculate shared key */
	if ((ret = TO_renew_shared_keys(LOCAL_ECC_KEY_INDEX, REMOTE_ECC_KEY_INDEX))
			!= TORSP_SUCCESS) {
		fprintf(stderr, "TO_renew_shared_keys() failed\n");
		return -1;
	}

	return 0;
}

/**
 * Simple secure function:
 * - Pad data (padding length >= 1) with padding length
 * - Secure message (encryption and authentication)
 */
static int encrypt(const uint8_t *data, const uint16_t data_len,
		uint8_t *data_encrypted, uint16_t *data_encrypted_len)
{
	int ret;
	uint8_t pad_len = TO_AES_BLOCK_SIZE - (data_len % TO_AES_BLOCK_SIZE);
	uint8_t i;

	memcpy(buf, data, data_len);

	if (pad_len == 0) {
		pad_len = TO_AES_BLOCK_SIZE;
	}

	/* Pad with padding length value */
	for (i = 0; i < pad_len; ++i) {
		buf[data_len + i] = pad_len;
	}

	/* Secure message */
	if ((ret = TO_secure_message(LOCAL_ECC_KEY_INDEX, LOCAL_ECC_KEY_INDEX, buf, 
					data_len + pad_len, data_encrypted, data_encrypted +
					TO_INITIALVECTOR_SIZE, data_encrypted +
					TO_INITIALVECTOR_SIZE + data_len + pad_len))
			!= TORSP_SUCCESS) {
		fprintf(stderr, "TO_secure_message() failed\n");
		return -1;
	}

	*data_encrypted_len = TO_INITIALVECTOR_SIZE + data_len + pad_len +
		TO_HMAC_SIZE;

	return 0;
}

/**
 * Simple un-secure function:
 * - Un-secure message (authentication and decryption)
 * - Remove data padding
 */
static int decrypt(const uint8_t *data_encrypted, const uint16_t data_encrypted_len,
		uint8_t *data, uint16_t *data_len)
{
	int ret;

	/* Unsecure message */
	if ((ret = TO_unsecure_message(LOCAL_ECC_KEY_INDEX, LOCAL_ECC_KEY_INDEX,
					data_encrypted, data_encrypted + TO_INITIALVECTOR_SIZE,
					data_encrypted_len - TO_INITIALVECTOR_SIZE - TO_HMAC_SIZE,
					data_encrypted + data_encrypted_len - TO_HMAC_SIZE, data))
			!= TORSP_SUCCESS) {
		fprintf(stderr, "TO_unsecure_message() failed\n");
		return -1;
	}

	*data_len = data_encrypted_len - TO_INITIALVECTOR_SIZE - TO_HMAC_SIZE;
	*data_len -= data[*data_len - 1];

	return 0;
}

/**
 * Simple function to send data with authentication and encryption.
 */
static int send_data_with_auth(const uint8_t *data, const uint16_t data_len)
{
	int ret = 0;
	payload_t *payload = (payload_t*)buf;
	uint8_t *data_encrypted = payload->data;
	uint16_t data_encrypted_len;

	/* Mutual authentication */
	if ((ret = auth()) != 0) {
		fprintf(stderr, "auth() failed\n");
		return ret;
	}

	/* Encrypt data */
	if ((ret = encrypt(data, data_len, data_encrypted, &data_encrypted_len))
			!= 0) {
		fprintf(stderr, "encrypt() failed\n");
		return ret;
	}

	payload->data_type = ECIES_CYPHERED_DATA;
	payload->data_size = htobe16(data_encrypted_len);

	/* Send encrypted data */
	if ((ret = send_data((uint8_t*)payload, PAYLOAD_SIZE(payload))) != 0) {
		fprintf(stderr, "send_data() failed\n");
		return ret;
	}

	return 0;
}

/**
 * Simple function to receive data with authentication and encryption.
 */
static int recv_data_with_auth(uint8_t *data, const uint16_t max_len,
		uint16_t *data_len)
{
	int ret = 0;
	uint16_t len;
	payload_t *payload = (payload_t*)buf;

	/* Mutual authentication */
	if ((ret = auth()) != 0) {
		fprintf(stderr, "auth() failed\n");
		return ret;
	}

	/* Receive encrypted data */
	if ((ret = recv_data((uint8_t*)payload, sizeof(buf), &len)) != 0) {
		fprintf(stderr, "recv_data() failed\n");
		return ret;
	}
	ASSERT((data_type_t)payload->data_type == ECIES_CYPHERED_DATA);
	ASSERT((uint16_t)DATA_SIZE(payload) <= max_len + TO_AES_BLOCK_SIZE -
			(max_len % TO_AES_BLOCK_SIZE) + TO_HMAC_SIZE);

	/* Decrypt data */
	if ((ret = decrypt(payload->data, DATA_SIZE(payload), data, data_len))
			!= 0) {
		fprintf(stderr, "decrypt() failed\n");
		return ret;
	}

	return 0;
}

#define SEND_DATA send_data_with_auth
#define RECV_DATA recv_data_with_auth

#else

#define SEND_DATA send_data
#define RECV_DATA recv_data

#endif

int main(int argc, const char *argv[])
{
	uint8_t data[256];
	uint16_t data_len;
	int ret = 1;

	if (init_data(argc, argv) != 0) {
		fprintf(stderr, "init_data() failed\n");
		goto fail;
	}

	if (TO_init() != TO_OK) {
		fprintf(stderr, "TO_init() failed\n");
		goto fail1;
	}

#ifdef TO_ECIES_CLIENT
	/* Send message */
	if (SEND_DATA((const uint8_t*)HELLO_MSG, sizeof(HELLO_MSG)) != 0) {
		fprintf(stderr, "SEND_DATA() failed\n");
		goto fail2;
	}
	/* Receive message */
	if (RECV_DATA(data, sizeof(data), &data_len) != 0) {
		fprintf(stderr, "RECV_DATA() failed\n");
		goto fail2;
	}
	fprintf(stderr, "data:\n------------\n%s\n------------\n", data);
#else
	/* Receive message */
	if (RECV_DATA(data, sizeof(data), &data_len) != 0) {
		fprintf(stderr, "RECV_DATA() failed\n");
		goto fail2;
	}
	fprintf(stderr, "data:\n------------\n%s\n------------\n", data);
	/* Send message */
	if (SEND_DATA((const uint8_t*)HELLO_MSG, sizeof(HELLO_MSG)) != 0) {
		fprintf(stderr, "SEND_DATA() failed\n");
		goto fail2;
	}
#endif

	ret = 0;

fail2:
	if (TO_fini() != TO_OK) {
		fprintf(stderr, "TO_fini() failed\n");
	}
fail1:
	if (fini_data() != TO_OK) {
		fprintf(stderr, "fini_data() failed\n");
	}
fail:
	return ret;
}
