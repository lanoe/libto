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
 * @file api_nvm.c
 * @brief Secure Element NVM functions.
 */

#include <core.h>

#ifndef TO_DISABLE_NVM
#ifndef TO_DISABLE_API_WRITE_NVM
TO_API int TO_write_nvm(const uint16_t offset, const void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;
	const uint16_t _offset = htobe16(offset);
	uint16_t data_length = 0;

	ret = TO_prepare_command_data(data_length, (uint8_t*)&_offset, sizeof(_offset));
	data_length += sizeof(_offset);
	ret |= TO_prepare_command_data(data_length, key, TO_AES_KEYSIZE);
	data_length += TO_AES_KEYSIZE;
	ret |= TO_prepare_command_data(data_length, data, length);
	data_length += length;
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_WRITE_NVM, data_length,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_READ_NVM
TO_API int TO_read_nvm(const uint16_t offset, void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE])
{
	int ret;
	uint8_t resp_status;
	const uint16_t _offset = htobe16(offset);
	const uint16_t _length = htobe16(length);
	uint16_t data_length = 0;

	ret = TO_prepare_command_data(data_length, (uint8_t*)&_offset, sizeof(_offset));
	data_length += sizeof(_offset);
	ret |= TO_prepare_command_data(data_length, (uint8_t*)&_length, sizeof(_length));
	data_length += sizeof(_length);
	ret |= TO_prepare_command_data(data_length, key, TO_AES_KEYSIZE);
	data_length += TO_AES_KEYSIZE;
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_READ_NVM, data_length,
			(uint16_t*)&length, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(data, TO_response_data, length);
	return resp_status;
}
#endif

#if !defined TO_DISABLE_API_WRITE_NVM || !defined TO_DISABLE_API_READ_NVM
TO_API int TO_get_nvm_size(uint16_t *size)
{
	int ret;
	uint16_t resp_data_len = sizeof(uint16_t);
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_GET_NVM_SIZE, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(size, TO_response_data, sizeof(*size));
	*size = be16toh(*size);
	return resp_status;
}
#endif
#endif // TO_DISABLE_NVM
