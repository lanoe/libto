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
 * @file api_system.c
 * @brief Secure Element system functions.
 */

#include <core.h>

#ifndef TO_DISABLE_TO_INFO
#ifndef TO_DISABLE_API_GET_SERIAL_NUMBER
int TO_get_serial_number(uint8_t serial_number[TO_SN_SIZE])
{
	int ret;
	uint16_t resp_data_len = TO_SN_SIZE;
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_GET_SN, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(serial_number, TO_response_data, TO_SN_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_PRODUCT_NUMBER
int TO_get_product_number(uint8_t product_number[TO_PN_SIZE])
{
	int ret;
	uint16_t resp_data_len = TO_PN_SIZE;
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_GET_PN, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(product_number, TO_response_data, TO_PN_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_HARDWARE_VERSION
int TO_get_hardware_version(
		uint8_t hardware_version[TO_HW_VERSION_SIZE])
{
	int ret;
	uint16_t resp_data_len = TO_HW_VERSION_SIZE;
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_GET_HW_VERSION, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(hardware_version, TO_response_data, TO_HW_VERSION_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_SOFTWARE_VERSION
int TO_get_software_version(uint8_t* major, uint8_t* minor,
		uint8_t* revision)
{
	int ret;
	uint16_t resp_data_len = TO_SW_VERSION_SIZE;
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_GET_SW_VERSION, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*major = TO_response_data[0];
	*minor = TO_response_data[1];
	*revision = TO_response_data[2];
	return resp_status;
}
#endif
#endif // TO_DISABLE_TO_INFO

#ifndef TO_DISABLE_API_GET_RANDOM
int TO_get_random(const uint16_t random_length, uint8_t* random)
{
	int ret;
	uint16_t resp_data_len = random_length;
	uint8_t resp_status;
	const uint16_t _random_length = htobe16(random_length);

	ret = TO_prepare_command_data(0, (uint8_t*)&_random_length,
			sizeof(_random_length));
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_RANDOM, 2,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(random, TO_response_data, random_length);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_STATUS_PIO_CONFIG
#ifndef TO_DISABLE_API_STATUS_PIO_CONFIG_SET
int TO_set_status_PIO_config(int enable,
		int opendrain, int ready_level, int idle_hz)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;
	uint16_t config = 0x00;

	if (enable)
		config |= TO_STATUS_PIO_ENABLE;
	if (opendrain)
		config |= TO_STATUS_PIO_HIGH_OPENDRAIN_MASK;
	if (ready_level)
		config |= TO_STATUS_PIO_READY_LEVEL_MASK;
	if (idle_hz)
		config |= TO_STATUS_PIO_IDLE_HZ_MASK;
	config <<= 8;
	config = htobe16(config);
	ret = TO_prepare_command_data(0, (uint8_t*)&config, sizeof(config));
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_SET_STATUS_PIO_CONFIG, sizeof(config),
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_STATUS_PIO_CONFIG_GET
int TO_get_status_PIO_config(int *enable,
		int *opendrain, int *ready_level, int *idle_hz)
{
	int ret;
	uint16_t resp_data_len = 2;
	uint8_t resp_status;

	ret = TO_send_command(TOCMD_GET_STATUS_PIO_CONFIG, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*enable = ((TO_response_data[0] & TO_STATUS_PIO_ENABLE)
			== TO_STATUS_PIO_ENABLE);
	*opendrain = ((TO_response_data[0]
				& TO_STATUS_PIO_HIGH_OPENDRAIN_MASK) != 0);
	*ready_level = ((TO_response_data[0]
				& TO_STATUS_PIO_READY_LEVEL_MASK) != 0);
	*idle_hz = ((TO_response_data[0]
				& TO_STATUS_PIO_IDLE_HZ_MASK) != 0);
	return resp_status;
}
#endif
#endif // TO_ENABLE_STATUS_PIO_CONFIG
