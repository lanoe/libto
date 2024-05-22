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
 * @file api_hash.c
 * @brief Secure Element hash computation functions.
 */

#include <core.h>

#ifndef TO_DISABLE_SHA256
#ifndef TO_DISABLE_API_SHA256
int TO_sha256(const uint8_t* data, const uint16_t data_length,
		uint8_t* sha256)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = data_length;
	uint16_t resp_data_len = TO_SHA256_HASHSIZE;

	ret = TO_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_SHA256, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(sha256, TO_response_data, TO_SHA256_HASHSIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_SHA256_INIT_UPDATE_FINAL
int TO_sha256_init(void)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_send_command(TOCMD_SHA256_INIT, 0,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_sha256_update(const uint8_t* data, const uint16_t length)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = length;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, data, length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_SHA256_UPDATE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_sha256_final(uint8_t* sha256)
{
	int ret;
	uint16_t resp_data_len = TO_SHA256_HASHSIZE;
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_SHA256_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(sha256, TO_response_data, TO_SHA256_HASHSIZE);
	return resp_status;
}
#endif
#endif // TO_DISABLE_SHA256
