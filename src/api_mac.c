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
 * @file api_mac.c
 * @brief Secure Element MAC (Message Authentication Code) functions.
 */

#include <core.h>

#ifndef TO_DISABLE_HMAC
#ifndef TO_DISABLE_API_COMPUTE_HMAC
int TO_compute_hmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t hmac_data[32])
{
	int ret;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = TO_HMAC_SIZE;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_COMPUTE_HMAC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(hmac_data, TO_response_data, TO_HMAC_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_COMPUTE_HMAC_INIT_UPDATE_FINAL
int TO_compute_hmac_init(uint8_t key_index)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_COMPUTE_HMAC_INIT, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_compute_hmac_update(const uint8_t* data, uint16_t length)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data(0, data, length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_COMPUTE_HMAC_UPDATE, length,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_compute_hmac_final(uint8_t hmac[TO_HMAC_SIZE])
{
	int ret;
	uint16_t resp_data_len = TO_HMAC_SIZE;
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_COMPUTE_HMAC_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(hmac, TO_response_data, TO_HMAC_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_HMAC
int TO_verify_hmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t hmac_data[32])
{
	int ret;
	uint16_t cmd_len = data_length + TO_HMAC_SIZE + 1;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, data, data_length);
	ret |= TO_prepare_command_data(data_length + 1, hmac_data,
			TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_HMAC, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_HMAC_INIT_UPDATE_FINAL
int TO_verify_hmac_init(uint8_t key_index)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_HMAC_INIT, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_verify_hmac_update(const uint8_t* data, uint16_t length)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data(0, data, length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_HMAC_UPDATE, length,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_verify_hmac_final(const uint8_t hmac[TO_HMAC_SIZE])
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data(0, hmac, TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_HMAC_FINAL, TO_HMAC_SIZE,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_HMAC

#ifndef TO_DISABLE_CMAC
#ifndef TO_DISABLE_API_COMPUTE_CMAC
int TO_compute_cmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t cmac_data[TO_CMAC_SIZE])
{
	int ret;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = TO_CMAC_SIZE;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_COMPUTE_CMAC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(cmac_data, TO_response_data, TO_CMAC_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CMAC
int TO_verify_cmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t cmac_data[TO_CMAC_SIZE])
{
	int ret;
	uint16_t cmd_len = data_length + TO_CMAC_SIZE + 1;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, data, data_length);
	ret |= TO_prepare_command_data(data_length + 1, cmac_data,
			TO_CMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_CMAC, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_CMAC
