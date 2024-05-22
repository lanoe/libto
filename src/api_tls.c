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
 * @file api_tls.c
 * @brief Secure Element TLS functions.
 */

#include <core.h>

#ifndef TO_DISABLE_TLS
int TO_set_tls_server_random( uint8_t random[TO_TLS_RANDOM_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, random, TO_TLS_RANDOM_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_SET_SERVER_RANDOM,
			TO_TLS_RANDOM_SIZE, &resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_set_tls_server_eph_pub_key(uint8_t key_index,
		uint8_t ecc_params[TO_TLS_SERVER_PARAMS_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = TO_INDEX_SIZE + TO_TLS_SERVER_PARAMS_SIZE +
		TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data(TO_INDEX_SIZE, ecc_params,
			TO_TLS_SERVER_PARAMS_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data(
			TO_INDEX_SIZE + TO_TLS_SERVER_PARAMS_SIZE,
			signature, TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_SET_SERVER_EPUBLIC_KEY, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_get_tls_random_and_store(
		uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t random[TO_TLS_RANDOM_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_RANDOM_SIZE - TO_TIMESTAMP_SIZE;

	ret = TO_prepare_command_data(0, timestamp, TO_TIMESTAMP_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_GET_RANDOM_AND_STORE,
			TO_TIMESTAMP_SIZE, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(random, timestamp, TO_TIMESTAMP_SIZE);
	secure_memcpy(random + TO_TIMESTAMP_SIZE, TO_response_data,
			TO_TLS_RANDOM_SIZE - TO_TIMESTAMP_SIZE);
	return resp_status;
}

int TO_get_tls_master_secret(
		uint8_t master_secret[TO_TLS_MASTER_SECRET_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_MASTER_SECRET_SIZE;

	ret = TO_prepare_command_data_byte(0, 0x00);
	if (ret != TO_OK)
		return ret;
	ret = TO_send_command(TOCMD_TLS_GET_MASTER_SECRET, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(master_secret, TO_response_data,
			TO_TLS_MASTER_SECRET_SIZE);
	return resp_status;
}

int TO_renew_tls_keys(const uint8_t key_index, const uint8_t enc_key_index,
		const uint8_t dec_key_index)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data_byte(1, enc_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data_byte(2, dec_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_RENEW_KEYS, 3,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_renew_tls_keys_ecdhe(const uint8_t kpriv_index,
		const uint8_t kpub_index, const uint8_t enc_key_index,
		const uint8_t dec_key_index)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, kpriv_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data_byte(1, kpub_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data_byte(2, enc_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data_byte(3, dec_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_RENEW_KEYS_ECDHE, 4,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_tls_calculate_finished(const int from,
		const uint8_t handshake_hash[TO_HASH_SIZE],
		uint8_t finished[TO_TLS_FINISHED_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_FINISHED_SIZE;

	ret = TO_prepare_command_data_byte(0, from);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data(1, handshake_hash, TO_HASH_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_CALCULATE_FINISHED,
			1 + TO_HASH_SIZE, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(finished, TO_response_data, TO_TLS_FINISHED_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_TLS_OPTIMIZED
int TO_tls_reset(void)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_send_command(TOCMD_TLS_RESET, 0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_set_mode(const TO_tls_mode_t mode)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, mode);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_SET_MODE,
			sizeof(uint8_t), &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_get_client_hello(const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t *client_hello, uint16_t *client_hello_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_CLIENT_HELLO_MAXSIZE;

	ret = TO_prepare_command_data(0, timestamp, TO_TIMESTAMP_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_GET_CLIENT_HELLO,
			TO_TIMESTAMP_SIZE, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(client_hello, TO_response_data, resp_data_len);
	*client_hello_len = resp_data_len;
	return resp_status;
}

int TO_tls_handle_hello_verify_request(const uint8_t *hello_verify_request,
		const uint32_t hello_verify_request_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, hello_verify_request,
			hello_verify_request_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_HELLO_VERIFY_REQUEST,
			hello_verify_request_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_server_hello(const uint8_t *server_hello,
		const uint32_t server_hello_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, server_hello, server_hello_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_SERVER_HELLO,
			server_hello_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_server_certificate_init(
		const uint8_t server_certificate_init[TO_TLS_SERVER_CERTIFICATE_INIT_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, server_certificate_init,
			TO_TLS_SERVER_CERTIFICATE_INIT_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_SERVER_CERTIFICATE_INIT,
			TO_TLS_SERVER_CERTIFICATE_INIT_SIZE,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_server_certificate_update(
		const uint8_t *server_certificate_update,
		const uint32_t server_certificate_update_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, server_certificate_update,
			server_certificate_update_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_SERVER_CERTIFICATE_UPDATE,
			server_certificate_update_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_server_certificate_final(void)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_send_command(TOCMD_TLS_HANDLE_SERVER_CERTIFICATE_FINAL,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_server_key_exchange(const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, server_key_exchange,
			server_key_exchange_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_SERVER_KEY_EXCHANGE,
			server_key_exchange_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_certificate_request(const uint8_t *certificate_request,
		const uint32_t certificate_request_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, certificate_request,
			certificate_request_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_CERTIFICATE_REQUEST,
			certificate_request_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_server_hello_done(
		const uint8_t server_hello_done[TO_TLS_SERVER_HELLO_DONE_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, server_hello_done,
			TO_TLS_SERVER_HELLO_DONE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_SERVER_HELLO_DONE,
			TO_TLS_SERVER_HELLO_DONE_SIZE,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_get_certificate(
		uint8_t *certificate, uint16_t *certificate_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_MAXSIZE;

	ret = TO_send_command(TOCMD_TLS_GET_CERTIFICATE,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(certificate, TO_response_data, resp_data_len);
	*certificate_len = resp_data_len;
	return resp_status;
}

int TO_tls_get_certificate_init(
		uint8_t certificate[TO_TLS_CLIENT_CERTIFICATE_INIT_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_CLIENT_CERTIFICATE_INIT_SIZE;

	ret = TO_send_command(TOCMD_TLS_GET_CERTIFICATE_INIT,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != TO_TLS_CLIENT_CERTIFICATE_INIT_SIZE)
		return TORSP_INVALID_LEN;

	secure_memcpy(certificate, TO_response_data, TO_TLS_CLIENT_CERTIFICATE_INIT_SIZE);
	return resp_status;
}

int TO_tls_get_certificate_update(
		uint8_t *certificate, uint16_t *certificate_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_LIB_INTERNAL_IO_BUFFER_SIZE - TO_TLS_HANDSHAKE_HEADER_SIZE;
	uint16_t len = htobe16(resp_data_len);

	ret = TO_prepare_command_data(0, (unsigned char*)&len, sizeof(uint16_t));
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_GET_CERTIFICATE_UPDATE,
			sizeof(uint16_t), &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(certificate, TO_response_data, resp_data_len);
	*certificate_len = resp_data_len;
	return resp_status;
}

int TO_tls_get_certificate_final(void)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_send_command(TOCMD_TLS_GET_CERTIFICATE_FINAL,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_get_client_key_exchange(
		uint8_t *client_key_exchange, uint16_t *client_key_exchange_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_CLIENT_KEY_EXCHANGE_MAXSIZE;

	ret = TO_send_command(TOCMD_TLS_GET_CLIENT_KEY_EXCHANGE,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(client_key_exchange, TO_response_data, resp_data_len);
	*client_key_exchange_len = resp_data_len;
	return resp_status;
}

int TO_tls_get_certificate_verify(
		uint8_t certificate_verify[TO_TLS_CERTIFICATE_VERIFY_MAXSIZE],
		uint16_t *certificate_verify_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_CERTIFICATE_VERIFY_MAXSIZE;

	ret = TO_send_command(TOCMD_TLS_GET_CERTIFICATE_VERIFY,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(certificate_verify, TO_response_data, resp_data_len);
	*certificate_verify_len = resp_data_len;
	return resp_status;
}

int TO_tls_get_change_cipher_spec(
		uint8_t change_cipher_spec[TO_TLS_CHANGE_CIPHER_SPEC_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_CHANGE_CIPHER_SPEC_SIZE;

	ret = TO_send_command(TOCMD_TLS_GET_CHANGE_CIPHER_SPEC,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(change_cipher_spec, TO_response_data,
			TO_TLS_CHANGE_CIPHER_SPEC_SIZE);
	return resp_status;
}

int TO_tls_get_finished(
		uint8_t finished[TO_TLS_FINISHED_PAYLOAD_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_TLS_FINISHED_PAYLOAD_SIZE;

	ret = TO_send_command(TOCMD_TLS_GET_FINISHED,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(finished, TO_response_data, TO_TLS_FINISHED_PAYLOAD_SIZE);
	return resp_status;
}

int TO_tls_handle_change_cipher_spec(
		const uint8_t change_cipher_spec[TO_TLS_CHANGE_CIPHER_SPEC_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, change_cipher_spec,
			TO_TLS_CHANGE_CIPHER_SPEC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_CHANGE_CIPHER_SPEC,
			TO_TLS_CHANGE_CIPHER_SPEC_SIZE,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_handle_finished(
		const uint8_t finished[TO_TLS_FINISHED_PAYLOAD_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, finished,
			TO_TLS_FINISHED_PAYLOAD_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_HANDLE_FINISHED,
			TO_TLS_FINISHED_PAYLOAD_SIZE,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_secure_message(const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t* data, const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len;
	uint16_t padding_len;

	padding_len = TO_AES_BLOCK_SIZE - ((data_len + 1) % TO_AES_BLOCK_SIZE);
	if (padding_len == TO_AES_BLOCK_SIZE) {
		padding_len = 0;
	}
	resp_data_len = TO_INITIALVECTOR_SIZE + data_len + TO_HMAC_SIZE
		+ padding_len + 1;

	ret = TO_prepare_command_data(0, header, TO_TLS_HEADER_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_prepare_command_data(TO_TLS_HEADER_SIZE, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_SECURE_MESSAGE,
			TO_TLS_HEADER_SIZE + data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(initial_vector, TO_response_data, TO_INITIALVECTOR_SIZE);
	*cryptogram_len = resp_data_len - TO_INITIALVECTOR_SIZE;
	secure_memcpy(cryptogram, TO_response_data + TO_INITIALVECTOR_SIZE,
			*cryptogram_len);
	return resp_status;
}

int TO_tls_secure_message_init(const uint8_t header[TO_TLS_HEADER_SIZE],
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_INITIALVECTOR_SIZE;

	ret = TO_prepare_command_data(0, header, TO_TLS_HEADER_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_SECURE_MESSAGE_INIT, TO_TLS_HEADER_SIZE,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != TO_INITIALVECTOR_SIZE)
		return TORSP_INVALID_LEN;

	secure_memcpy(initial_vector, TO_response_data, TO_INITIALVECTOR_SIZE);
	return resp_status;
}

int TO_tls_secure_message_update(const uint8_t* data, const uint16_t data_len,
		uint8_t *cryptogram)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = data_len;

	ret = TO_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_SECURE_MESSAGE_UPDATE, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != data_len)
		return TORSP_INVALID_LEN;

	secure_memcpy(cryptogram, TO_response_data, data_len);
	return resp_status;
}

int TO_tls_secure_message_final(const uint8_t* data, const uint16_t data_len,
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_AES_BLOCK_SIZE + TO_HMAC_SIZE;

	ret = TO_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_SECURE_MESSAGE_FINAL, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*cryptogram_len = resp_data_len;
	secure_memcpy(cryptogram, TO_response_data, *cryptogram_len);
	return resp_status;
}

int TO_tls_unsecure_message(const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = cryptogram_len - TO_HMAC_MINSIZE - 1;
	uint16_t cmd_len = 0;

	ret = TO_prepare_command_data(cmd_len, header, TO_TLS_HEADER_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_TLS_HEADER_SIZE;
	ret = TO_prepare_command_data(cmd_len, initial_vector,
			TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TO_prepare_command_data(cmd_len, cryptogram, cryptogram_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += cryptogram_len;
	ret = TO_send_command(TOCMD_TLS_UNSECURE_MESSAGE,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	secure_memcpy(data, TO_response_data, *data_len);
	return resp_status;
}

int TO_tls_unsecure_message_init(const uint16_t cryptogram_len,
		const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t cmd_len = 0;
	uint16_t _cryptogram_len = htobe16(cryptogram_len);

	ret = TO_prepare_command_data(cmd_len, (uint8_t*)&_cryptogram_len, sizeof(uint16_t));
	if (TO_OK != ret)
		return ret;
	cmd_len += sizeof(uint16_t);
	ret = TO_prepare_command_data(cmd_len, header, TO_TLS_HEADER_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_TLS_HEADER_SIZE;
	ret = TO_prepare_command_data(cmd_len, initial_vector, TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TO_prepare_command_data(cmd_len, last_block_iv, TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TO_prepare_command_data(cmd_len, last_block, TO_AES_BLOCK_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_AES_BLOCK_SIZE;
	ret = TO_send_command(TOCMD_TLS_UNSECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

int TO_tls_unsecure_message_update(const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = cryptogram_len;

	ret = TO_prepare_command_data(0, cryptogram, cryptogram_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_TLS_UNSECURE_MESSAGE_UPDATE, cryptogram_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	secure_memcpy(data, TO_response_data, *data_len);
	return resp_status;
}

int TO_tls_unsecure_message_final(void)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_send_command(TOCMD_TLS_UNSECURE_MESSAGE_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}
#endif
