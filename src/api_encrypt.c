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
 * @file api_encrypt.c
 * @brief Secure Element encryption and message securisation functions.
 */

#include <core.h>

#ifndef TO_DISABLE_AES_ENCRYPT
#ifndef TO_DISABLE_API_AES_ENCRYPT
int TO_aes_encrypt(const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = data_length + TO_INITIALVECTOR_SIZE;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_AESCBC_ENCRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(initial_vector, TO_response_data, TO_INITIALVECTOR_SIZE);
	secure_memcpy(cryptogram, TO_response_data + TO_INITIALVECTOR_SIZE,
			data_length);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES_IV_ENCRYPT
int TO_aes_iv_encrypt(const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 1 + TO_INITIALVECTOR_SIZE + data_length;
	uint16_t resp_data_len = data_length;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, initial_vector,
			TO_INITIALVECTOR_SIZE);
	ret |= TO_prepare_command_data(1 + TO_INITIALVECTOR_SIZE,
			data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_AESCBC_IV_ENCRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(cryptogram, TO_response_data, data_length);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES_DECRYPT
int TO_aes_decrypt(const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = cryptogram_length + TO_INITIALVECTOR_SIZE + 1;
	uint16_t resp_data_len = cryptogram_length;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, initial_vector,
			TO_INITIALVECTOR_SIZE);
	ret |= TO_prepare_command_data(1 + TO_INITIALVECTOR_SIZE,
			cryptogram, cryptogram_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_AESCBC_DECRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(data, TO_response_data, resp_data_len);
	return resp_status;
}
#endif
#endif // TO_DISABLE_AES_ENCRYPT

#ifndef TO_DISABLE_SEC_MSG
#ifndef TO_DISABLE_API_SECURE_MESSAGE
int TO_secure_message(const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint8_t hmac[TO_HMAC_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = data_length + 2;
	uint16_t resp_data_len = data_length + TO_INITIALVECTOR_SIZE
		+ TO_HMAC_SIZE;

	ret = TO_prepare_command_data_byte(0, aes_key_index);
	ret |= TO_prepare_command_data_byte(1, hmac_key_index);
	ret |= TO_prepare_command_data(2, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_SECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(initial_vector, TO_response_data, TO_INITIALVECTOR_SIZE);
	secure_memcpy(cryptogram, TO_response_data + TO_INITIALVECTOR_SIZE,
			data_length);
	secure_memcpy(hmac, TO_response_data + TO_INITIALVECTOR_SIZE
			+ data_length, TO_HMAC_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_UNSECURE_MESSAGE
int TO_unsecure_message(const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t hmac[TO_HMAC_SIZE],
		uint8_t* data)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 2 + TO_INITIALVECTOR_SIZE + cryptogram_length +
		TO_HMAC_SIZE;
	uint16_t resp_data_len = cryptogram_length;

	ret = TO_prepare_command_data_byte(0, aes_key_index);
	ret |= TO_prepare_command_data_byte(1, hmac_key_index);
	ret |= TO_prepare_command_data(2, initial_vector,
			TO_INITIALVECTOR_SIZE);
	ret |= TO_prepare_command_data(2 + TO_INITIALVECTOR_SIZE,
			cryptogram, cryptogram_length);
	ret |= TO_prepare_command_data(2 + TO_INITIALVECTOR_SIZE
			+ cryptogram_length, hmac, TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_UNSECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(data, TO_response_data, cryptogram_length);
	return resp_status;
}
#endif
#endif // TO_DISABLE_SEC_MSG
