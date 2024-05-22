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
 * @file api_lora.c
 * @brief Secure Element LoRa functions.
 */

#include <core.h>

#ifndef TO_DISABLE_LORA
TO_API int TO_lora_compute_mic(const uint8_t *data, uint16_t data_length,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t mic[TO_LORA_MIC_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = TO_AES_BLOCK_SIZE + data_length + 1;
	uint16_t resp_data_len = TO_LORA_MIC_SIZE;
	static uint8_t mic_block_b0[] = {
		0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	const uint32_t _address = htole32(address);
	const uint32_t _seq_counter = htole32(seq_counter);

	/* fills the block B0 according to lora specification */
	mic_block_b0[5] = direction;
	secure_memcpy(mic_block_b0 + 6, (uint8_t*)&_address, sizeof(_address));
	secure_memcpy(mic_block_b0 + 10, (uint8_t*)&_seq_counter, sizeof(_seq_counter));
	mic_block_b0[15] = data_length % (1 << 8);

	ret = TO_prepare_command_data_byte(0, 0x01); /* for a non join-request
						      mic, this field
						      shouldn't be null */
	ret |= TO_prepare_command_data(1, mic_block_b0, sizeof(mic_block_b0));
	ret |= TO_prepare_command_data(1 + sizeof(mic_block_b0),
			data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_LORA_COMPUTE_MIC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(mic, TO_response_data, TO_LORA_MIC_SIZE);
	return resp_status;
}

TO_API int TO_lora_encrypt_payload(const uint8_t *data,
		uint16_t data_length, const uint8_t *fport,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t *enc_buffer)
{
	int i, ret;
	uint8_t resp_status;
	uint8_t block_count = (data_length + (TO_AES_BLOCK_SIZE
				- (data_length % TO_AES_BLOCK_SIZE)))
		/ TO_AES_BLOCK_SIZE; /* ceil data length / AES block size
					   to compute the block count with
					   padding for AES encryption
					   according to LoRa specification */
	uint16_t cmd_len = block_count * TO_AES_BLOCK_SIZE + 1;
	uint16_t resp_data_len = block_count * TO_AES_BLOCK_SIZE;
	const uint32_t _address = htole32(address);
	const uint32_t _seq_counter = htole32(seq_counter);

	ret = TO_set_command_data(0, 0x00, cmd_len);
	ret |= TO_prepare_command_data_byte(0, *fport);
	for (i = 0; i < block_count; i++) {
		ret |= TO_prepare_command_data_byte(
				1 + i * TO_AES_BLOCK_SIZE,
				0x01);
		ret |= TO_prepare_command_data_byte(
				1 + i * TO_AES_BLOCK_SIZE + 5,
				direction);
		ret |= TO_prepare_command_data(
				1 + i * TO_AES_BLOCK_SIZE + 6,
				(uint8_t*)&_address, sizeof(_address));
		ret |= TO_prepare_command_data(
				1 + i * TO_AES_BLOCK_SIZE + 10,
				(uint8_t*)&_seq_counter, sizeof(_seq_counter));
		ret |= TO_prepare_command_data_byte(
				1 + i * TO_AES_BLOCK_SIZE + 15,
				(uint8_t)(i + 1));
	}
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_LORA_ENCRYPT_PAYLOAD,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	/* Applies xor function to finalize the encryption */
	for (i = 0; i < data_length; i++)
		enc_buffer[i] = data[i] ^ TO_response_data[i];
	return resp_status;
}

TO_API int TO_lora_join_compute_mic(const uint8_t *data,
		uint16_t data_length, uint8_t mic[TO_LORA_MIC_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = TO_LORA_MIC_SIZE;

	ret = TO_prepare_command_data_byte(0, 0x00); /* for a join-request
						      message, this field
						      should be null to inform
						      the secure element that it
						      has to use the application
						      key */
	ret |= TO_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_LORA_COMPUTE_MIC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(mic, TO_response_data, TO_LORA_MIC_SIZE);
	return resp_status;
}

TO_API int TO_lora_decrypt_join(const uint8_t *data, uint16_t data_length,
		uint8_t *dec_buffer)
{
	int ret;
	uint8_t resp_status;

	ret = TO_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_LORA_DECRYPT_JOIN, data_length,
			&data_length, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(dec_buffer, TO_response_data, data_length);
	return resp_status;
}

TO_API int TO_lora_compute_shared_keys(const uint8_t *app_nonce,
		const uint8_t *net_id, uint16_t dev_nonce)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	/* Send the block to derive the network shared key (only 1 byte
	differs from the block needed to derive application shared key) */
	ret = TO_set_command_data(0, 0x00, TO_AES_BLOCK_SIZE);
	ret |= TO_prepare_command_data_byte(0, 0x01);
	ret |= TO_prepare_command_data(1, app_nonce,
			TO_LORA_APPNONCE_SIZE);
	ret |= TO_prepare_command_data(1 + TO_LORA_APPNONCE_SIZE, net_id,
			TO_LORA_NETID_SIZE);
	ret |= TO_prepare_command_data(1 + TO_LORA_APPNONCE_SIZE
			+ TO_LORA_NETID_SIZE, (unsigned char *)&dev_nonce,
			TO_LORA_DEVNONCE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_LORA_COMPUTE_SHARED_KEYS,
			TO_AES_BLOCK_SIZE, &resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif /* TO_DISABLE_LORA */

#if !defined(TO_DISABLE_LORA) || !defined(TO_DISABLE_LORA_OPTIMIZED)
TO_API int TO_lora_get_app_eui(uint8_t app_eui[TO_LORA_APPEUI_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_LORA_APPEUI_SIZE;

	ret = TO_send_command(TOCMD_LORA_GET_APPEUI, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(app_eui, TO_response_data, TO_LORA_APPEUI_SIZE);
	return resp_status;
}

TO_API int TO_lora_get_dev_eui(uint8_t dev_eui[TO_LORA_DEVEUI_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_LORA_DEVEUI_SIZE;

	ret = TO_send_command(TOCMD_LORA_GET_DEVEUI, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(dev_eui, TO_response_data, TO_LORA_DEVEUI_SIZE);
	return resp_status;
}
#endif /* !defined(TO_DISABLE_LORA) || !defined(TO_DISABLE_LORA_OPTIMIZED) */

#ifndef TO_DISABLE_LORA_OPTIMIZED
TO_API int TO_lora_get_join_request_phypayload(
		uint8_t data[TO_LORA_JOINREQUEST_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_LORA_JOINREQUEST_SIZE;

	ret = TO_send_command(TOCMD_LORA_GET_JOIN_REQUEST, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(data, TO_response_data, TO_LORA_JOINREQUEST_SIZE);
	return resp_status;
}

TO_API int TO_lora_handle_join_accept_phypayload(const uint8_t *data,
		const uint16_t data_length, uint8_t *dec_buffer)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = data_length - TO_LORA_MIC_SIZE;

	ret = TO_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_LORA_HANDLE_JOIN_ACCEPT, data_length,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(dec_buffer, TO_response_data, resp_data_len);
	return resp_status;
}

TO_API int TO_lora_secure_phypayload(const uint8_t mhdr,
		const uint8_t fctrl, const uint8_t *fopts, const uint8_t fport,
		const uint8_t *payload, const int payload_size,
		uint8_t *enc_buffer)
{
	int ret;
	uint8_t resp_status;
	uint16_t data_length = 0;
	uint16_t resp_data_len;
	uint8_t fopts_len = fctrl & 0xf;

	ret = TO_prepare_command_data_byte(data_length++, mhdr);
	ret |= TO_prepare_command_data_byte(data_length++, fctrl);

	/* FOpts is optional */
	if (fopts_len > 0) {
		if (fopts == NULL) {
			FPRINTF(stderr, "Missing frame options\n");
			return TO_ERROR;
		}
		ret |= TO_prepare_command_data(data_length, fopts,
				fopts_len);
		data_length += fopts_len;
	}

	/* Payload is optional, no FPort if missing */
	if (payload_size > 0) {
		if (payload == NULL) {
			FPRINTF(stderr, "Missing payload\n");
			return TO_ERROR;
		}
		ret |= TO_prepare_command_data_byte(data_length++, fport);
		ret |= TO_prepare_command_data(data_length, payload,
				payload_size);
		data_length += payload_size;
	}

	if (TO_OK != ret)
		return ret;
	resp_data_len = data_length + TO_LORA_DEVADDR_SIZE
		+ TO_LORA_FCNT_SIZE / 2 + TO_LORA_MIC_SIZE;
	ret = TO_send_command(TOCMD_LORA_SECURE_PHYPAYLOAD, data_length,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(enc_buffer, TO_response_data, resp_data_len);
	return resp_status;
}

TO_API int TO_lora_unsecure_phypayload(const uint8_t *data,
		const uint16_t data_length, uint8_t *dec_buffer)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = data_length - TO_LORA_MIC_SIZE;

	ret = TO_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_LORA_UNSECURE_PHYPAYLOAD, data_length,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(dec_buffer, TO_response_data, resp_data_len);
	return resp_status;
}
#endif /* TO_DISABLE_LORA_OPTIMIZED */
