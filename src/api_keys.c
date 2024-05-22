/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2017 Trusted Objects. All rights reserved.
 */

/**
 * @file api_keys.c
 * @brief Secure Element keys management functions.
 */

#include <core.h>

#ifndef TO_DISABLE_KEYS_MGMT
#ifndef TO_DISABLE_API_SET_REMOTE_PUBLIC_KEY
int TO_set_remote_public_key(const uint8_t key_index,
		const uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 1 + TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, public_key, TO_ECC_PUB_KEYSIZE);
	ret |= TO_prepare_command_data(1 + TO_ECC_PUB_KEYSIZE, signature,
			TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_SET_REMOTE_PUBLIC_KEY, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_RENEW_ECC_KEYS
int TO_renew_ecc_keys(const uint8_t key_index)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_RENEW_ECC_KEYS, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_PUBLIC_KEY
int TO_get_public_key(const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		uint8_t signature[TO_SIGNATURE_SIZE])
{
	int ret;
	uint16_t resp_data_len = TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_PUBLIC_KEY, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(public_key, TO_response_data, TO_ECC_PUB_KEYSIZE);
	secure_memcpy(signature, TO_response_data + TO_ECC_PUB_KEYSIZE,
			TO_SIGNATURE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_UNSIGNED_PUBLIC_KEY
int TO_get_unsigned_public_key(const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE])
{
	int ret;
	uint16_t resp_data_len = TO_ECC_PUB_KEYSIZE;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_UNSIGNED_PUBLIC_KEY, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(public_key, TO_response_data, TO_ECC_PUB_KEYSIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_RENEW_SHARED_KEYS
int TO_renew_shared_keys(const uint8_t key_index,
		const uint8_t public_key_index)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data_byte(1, public_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_RENEW_SHARED_KEYS, 2,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_KEYS_MGMT

#ifndef TO_DISABLE_FINGERPRINT
#ifndef TO_DISABLE_API_GET_KEY_FINGERPRINT
int TO_get_key_fingerprint(TO_key_type_t key_type,
		uint8_t key_index,
		uint8_t* fingerprint[TO_KEY_FINGERPRINT_SIZE])
{
	int ret;
	uint16_t resp_data_len = TO_KEY_FINGERPRINT_SIZE;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_type);
	ret |= TO_prepare_command_data_byte(1, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_KEY_FINGERPRINT, 2,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(fingerprint, TO_response_data, TO_KEY_FINGERPRINT_SIZE);
	return resp_status;
}
#endif
#endif // TO_DISABLE_FINGERPRINT
