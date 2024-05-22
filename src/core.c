/*
 *
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
 * @file core.c
 * @brief Secure Element API implementation using I2C wrapper for Secure
 * Element communications.
 */

#include <core.h>
#include <seclink.h>

unsigned char TO_io_buffer[TO_LIB_INTERNAL_IO_BUFFER_SIZE];
unsigned char *TO_command_data = TO_io_buffer + TO_CMDHEAD_SIZE;
unsigned char *TO_response_data = TO_io_buffer + TO_RSPHEAD_SIZE;

static TO_pre_command_hook _pre_command_hook = NULL;
static TO_post_write_hook _post_write_hook = NULL;
static TO_post_command_hook _post_command_hook = NULL;

#ifndef TO_CMD_MAX_PARAMS
#define TO_CMD_MAX_PARAMS 10
#endif

/*
 * Data parameters types to build command data buffer
 */
enum cmd_param_type_e {
	CMD_PARAM_PTR, /**< Pointer to a data buffer */
	CMD_PARAM_BYTE, /**< Single byte */
	CMD_PARAM_RANGE, /**< Bytes range to set to a defined value */
};

/*
 * Command data parameter description
 */
struct cmd_param_s {
	enum cmd_param_type_e type;
	uint16_t offset;
	void *data;
	uint16_t size;
};

/*
 * Data parameters description array, used to build command data buffer
 */
static struct cmd_param_s _cmd_param[TO_CMD_MAX_PARAMS];

/*
 * Last command parameter index in cmd_params
 */
static uint8_t _cmd_param_index = 0;

/*
 * Secure link bypassing
 */
static int _seclink_bypass = 0;

/*
 * Secure link status
 */
static int _seclink_ready = 0;

#ifdef TO_DEBUG
void hex_disp(const uint8_t *data, unsigned int size)
{
	unsigned int i;
#if defined(HEX_DISP_MAX_DISP_SIZE) && (HEX_DISP_MAX_DISP_SIZE)
	if (size > HEX_DISP_MAX_DISP_SIZE) {
		size = HEX_DISP_MAX_DISP_SIZE;
	}
#endif
	for(i = 0; i < size; i++) {
		if ((i) && (!(i%HEX_DISP_NB_COL))) {
			FPRINTF(stdout, "\n");
		}
		FPRINTF(stdout, "%02X ", data[i]);
	}
	FPRINTF(stdout, "\n");
}
void dump_buffer(const uint8_t *buf, unsigned int size)
{
	unsigned int i;
	for (i = 0; i < size; ++i) {
		if (!(i % 16)) {
			if (i)
				FPRINTF(stdout, "\n");
			FPRINTF(stdout, "%08x: ", (unsigned int)i);
		} else if (!(i % 8)) {
			FPRINTF(stdout, " ");
		}
		FPRINTF(stdout, "%02x ", buf[i]);
	}
	FPRINTF(stdout, "\n");
}

#endif /* TO_DEBUG */

int secure_memcmp(const void *s1, const void *s2, unsigned int n)
{
	unsigned int i;
	unsigned int successcnt = 0, failcnt = 0;

	if (n == 0)
		return 0;
	for (i = 0; i < n; i++) {
		if (((char*)s1)[i] == ((char*)s2)[i])
			successcnt++;
		else
			failcnt++;
	}

	if (failcnt)
		return -1;
	if (successcnt != n)
		return -1;
	return 0;
}

void *secure_memcpy(void *dest, const void *src, unsigned int n)
{
	unsigned int i;

	if (!dest || !src)
		return NULL;
	if (dest == src
			|| (dest < src && (char*)dest + n > (char*)src)
			|| (src < dest && (char*)src + n > (char*)dest))
		return NULL;
	for (i = 0; i < n; i++)
		((char*)dest)[i] = ((char*)src)[i];

	return dest;
}

void *secure_memmove(void *dest, const void *src, unsigned int n)
{
	int i;

	if (!dest || !src)
		return NULL;
	if (dest < src) {
		for (i = 0; (unsigned int)i < n; i++)
			((char*)dest)[i] = ((char*)src)[i];
	} else if (dest > src) {
		for (i = n - 1; i >= 0; i--)
			((char*)dest)[i] = ((char*)src)[i];
	}

	return dest;
}

void *secure_memset(void *s, int c, unsigned int n)
{
	volatile char *p = s;

	if (s != NULL) {
		while (n--)
			*p++ = c;
	}
	return s;
}

#ifdef TO_ENDIAN_RUNTIME_DETECT
int TO_byte_order = TO_BYTE_ORDER_LITTLE_ENDIAN;
static void detect_endianness(void)
{
	union {
		uint32_t intval;
		char rawval[sizeof(uint32_t)];
	} integer;
	integer.intval = 1;
	FPRINTF(stdout, "libTO detected endianness: ");
	if (integer.rawval[0]) {
		TO_byte_order = TO_BYTE_ORDER_LITTLE_ENDIAN;
		FPRINTF(stdout, "little, consider defining TO_LITTLE_ENDIAN\n");
	} else {
		TO_byte_order = TO_BYTE_ORDER_BIG_ENDIAN;
		FPRINTF(stdout, "big, consider defining TO_BIG_ENDIAN\n");
	}
}
#endif

int TO_init(void)
{
#ifdef TO_ENDIAN_RUNTIME_DETECT
	detect_endianness();
#endif
	return TO_data_init();
}

int TO_fini(void)
{
	_seclink_ready = 0;
	return TO_data_fini();
}

int TO_write(const void *data, unsigned int length)
{
	FPRINTF(stdout, "%s: ", __func__);
	HEX_DISP((const unsigned char*)data, length);
	return TO_data_write(data, length);
}

int TO_read(void *data, unsigned int length)
{
	int ret;
	ret = TO_data_read(data, length);
	FPRINTF(stdout, "%s: ", __func__);
	HEX_DISP((const unsigned char*)data, length);
	return ret;
}

int TO_last_command_duration(unsigned int *duration)
{
#ifdef TO_I2C_WRAPPER_LAST_COMMAND_DURATION
	int ret;
	ret = TO_data_last_command_duration(duration);
	if (ret == TO_OK) {
		FPRINTF(stdout, "%s: %d µs\n", __func__, *duration);
	}
	return ret;
#else
	*duration = 0;
	return TO_NOT_IMPLEMENTED;
#endif
}

#ifdef TO_I2C_WRAPPER_CONFIG
int TO_config(unsigned char i2c_addr, unsigned char misc_settings)
{
	TO_i2c_config_t config;
	config.i2c_addr = i2c_addr;
	config.misc_settings = misc_settings;
	return TO_data_config(&config);
}
#endif

int TO_seclink_reset(void)
{
	int ret;
	ret = TO_seclink_init();
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error: unable to initialize secure"
				" commands, error %X\n", __func__, ret);
		return ret;
	}
	_seclink_ready = 1;
	return TO_OK;
}

int TO_seclink_bypass(int bypass)
{
	int prev_state = _seclink_bypass;
	_seclink_bypass = bypass;
	return prev_state;
}

void TO_reset_command_data(void)
{
	_cmd_param_index = 0;
}

static int _check_cmd_param_index(void)
{
	if (_cmd_param_index >= TO_CMD_MAX_PARAMS) {
		FPRINTF(stderr, "%s error: command max parameters exceeded\n",
				__func__);
		TO_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	return TO_OK;
}

int TO_prepare_command_data(uint16_t offset,
		const unsigned char *data, uint16_t len)
{
	int ret;

	/* Checks if command headers and data doesn't exceed buffer size */
	if (TO_CMDHEAD_SIZE + offset + len
			> TO_LIB_INTERNAL_IO_BUFFER_SIZE) {
		FPRINTF(stderr, "%s error: command data length exceeds internal"
			       " I/O buffer size\n", __func__);
		TO_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	/* Save command parameter details */
	ret = _check_cmd_param_index();
	if (ret != TO_OK)
		return ret;
	_cmd_param[_cmd_param_index].type = CMD_PARAM_PTR;
	_cmd_param[_cmd_param_index].offset = offset;
	_cmd_param[_cmd_param_index].data = (void *)data;
	_cmd_param[_cmd_param_index].size = len;
	_cmd_param_index++;

	return TO_OK;
}

int TO_prepare_command_data_byte(uint16_t offset, const char byte)
{
	int ret;

	/* Checks if command headers and data byte doesn't exceed buffer size */
	if (TO_CMDHEAD_SIZE + offset
			> TO_LIB_INTERNAL_IO_BUFFER_SIZE) {
		FPRINTF(stderr, "%s error: command data byte exceeds internal"
				" I/O buffer size\n", __func__);
		TO_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	/* Save command parameter details */
	ret = _check_cmd_param_index();
	if (ret != TO_OK)
		return ret;
	_cmd_param[_cmd_param_index].type = CMD_PARAM_BYTE;
	_cmd_param[_cmd_param_index].offset = offset;
	_cmd_param[_cmd_param_index].data = (void *)(long)byte;
	_cmd_param_index++;

	return TO_OK;
}

int TO_set_command_data(uint16_t offset, const char byte, uint16_t len)
{
	int ret;

	/* Checks if command headers and data doesn't exceed buffer size */
	if (TO_CMDHEAD_SIZE + offset + len
			> TO_LIB_INTERNAL_IO_BUFFER_SIZE) {
		FPRINTF(stderr, "%s error: command data range exceeds internal"
				" I/O buffer size\n", __func__);
		TO_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	/* Save command parameter details */
	ret = _check_cmd_param_index();
	if (ret != TO_OK)
		return ret;
	_cmd_param[_cmd_param_index].type = CMD_PARAM_RANGE;
	_cmd_param[_cmd_param_index].offset = offset;
	_cmd_param[_cmd_param_index].data = (void *)(long)byte;
	_cmd_param[_cmd_param_index].size = len;
	_cmd_param_index++;

	return TO_OK;
}

/**
 * _write_command() - Write command to TO
 * @len: Command and data length
 *
 * This function first checks if internal I/O buffer size is greater than
 * command length, taking into account secure link data overhead if secure
 * command bypassing is disabled.
 * The command is secured if secure link bypassing is disabled, then written
 * to TO.
 *
 * Return: TO_OK on success
 */
static int _write_command(uint16_t len)
{
	int ret;
	uint16_t fullcmd_size;

	if (!_seclink_bypass) {
		if (!_seclink_ready) {
			ret = TO_seclink_reset();
			if (ret != TO_OK) {
				return ret;
			}
		}
		fullcmd_size = TO_seclink_compute_cmd_size(len);
	} else {
		fullcmd_size = len;
	}
	if (fullcmd_size > TO_LIB_INTERNAL_IO_BUFFER_SIZE) {
		FPRINTF(stderr, "%s error: length (%d) exceeds internal I/O"
				" buffer size (%d)\n", __func__,
				fullcmd_size,
				TO_LIB_INTERNAL_IO_BUFFER_SIZE);
		return TO_MEMORY_ERROR;
	}
	if (!_seclink_bypass) {
		ret = TO_seclink_secure(TO_io_buffer, len);
		if (ret != TO_OK) {
			FPRINTF(stderr, "%s error %X:"
					" unable to secure link\n",
					__func__, ret);
			return ret;
		}
	}

	return TO_data_write(TO_io_buffer, fullcmd_size);
}

/**
 * _read_response() - Read Secure Element response
 * @len: Expected response length
 *
 * This function first checks if internal I/O buffer size is greater than
 * response length, taking into account secure link data overhead if secure
 * command bypassing is disabled.
 * The response is read from TO, then is unsecured if secure link
 * bypassing is disabled.
 *
 * Return: TO_OK on success
 */
static int _read_response(uint16_t len)
{
	int ret;
	uint16_t fullrsp_size;

	if (!_seclink_bypass)
		fullrsp_size = TO_seclink_compute_rsp_size(len);
	else
		fullrsp_size = len;
	if (fullrsp_size < len) {
		FPRINTF(stderr, "%s data length overflow\n", __func__);
		return TO_MEMORY_ERROR;
	}
	if (fullrsp_size > TO_LIB_INTERNAL_IO_BUFFER_SIZE) {
		FPRINTF(stderr, "%s error: length (%d) exceeds internal I/O"
				" buffer size (%d)\n", __func__,
				fullrsp_size,
				TO_LIB_INTERNAL_IO_BUFFER_SIZE);
		return TO_MEMORY_ERROR;
	}
	ret = TO_data_read(TO_io_buffer, fullrsp_size);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s error %X: unable to read data\n",
				__func__, ret);
		return ret;
	}
	if (!_seclink_bypass) {
		ret = TO_seclink_unsecure(TO_io_buffer);
		if (ret != TO_OK) {
			if ((ret & 0x00FF) != TORSP_SECLINK_RENEW_KEY) {
				FPRINTF(stderr, "%s error %X:"
						" unable to unsecure link\n",
						__func__, ret);
			}
			return ret;
		}
	}

	return TO_OK;
}

static void _prepare_command_data_buffer(void)
{
	uint8_t i;
	struct cmd_param_s *param;
	for (i = 0; i < _cmd_param_index; i++) {
		param = &_cmd_param[i];
		switch (param->type) {
		case CMD_PARAM_PTR:
			secure_memcpy(TO_command_data + param->offset,
					(char *)param->data, param->size);
			break;
		case CMD_PARAM_BYTE:
			TO_command_data[param->offset] =
				(char)(long)param->data;
			break;
		case CMD_PARAM_RANGE:
			secure_memset(TO_command_data + param->offset,
					(char)(long)param->data,
					param->size);
			break;
		}
	}
}

static int _send_command(const uint16_t cmd, uint16_t cmd_data_len,
		uint16_t *resp_data_len, uint8_t *resp_status)
{
	uint16_t data_len;
	unsigned int status;
	uint16_t _cmd;
	uint16_t _cmd_data_len;
	uint16_t *_resp_data_len;

	if (_pre_command_hook)
		_pre_command_hook(cmd, cmd_data_len);

	/*
	 * Prepare inputs
	 */
	*resp_status = 0;
	_cmd = htobe16(cmd);
	_cmd_data_len = htobe16(cmd_data_len);
	_prepare_command_data_buffer();

	/*
	 * Command headers:
	 *  CMD: 2
	 *  Lc: 2, to encode number of bytes of data
	 *  RES: 1, reserved
	 *  Data: Lc
	 * Read the Secure Element Datasheet, 7.2 - Command fields
	 */
	data_len = TO_CMDHEAD_SIZE + cmd_data_len;
	secure_memcpy(TO_io_buffer, (uint8_t*)&_cmd, sizeof(cmd));
	secure_memcpy(TO_io_buffer + 2, (uint8_t*)&_cmd_data_len,
			sizeof(_cmd_data_len));
	TO_io_buffer[4] = 0x0; /* RESERVED */
	FPRINTF(stdout, "%s write:\n", __func__);
	HEX_DISP(TO_io_buffer, data_len);
	/* Write command and data */
	status = _write_command(data_len);
	if (TO_OK != status) {
		FPRINTF(stderr, "%s(cmd=%04X) write error %04X\n",
				__func__, cmd, status);
		if (TO_MEMORY_ERROR == status)
			return TO_MEMORY_ERROR;
		else
			return TO_DEVICE_WRITE_ERROR;
	}

	if (_post_write_hook)
		_post_write_hook(cmd, cmd_data_len);

	/*
	 * Response headers:
	 *  Lr: 2, length of response data
	 *  ST: 1, status of the command (success, failed ...)
	 *  RES: 1, reserved
	 *  Data: Lr
	 * Read the Secure Element Datasheet, 7.3 - Response fields
	 */
	data_len = TO_RSPHEAD_SIZE + *resp_data_len;
	/* Size overflow */
	if (data_len < *resp_data_len) {
		FPRINTF(stderr, "%s(cmd=%04X) response length overflow\n",
				__func__, cmd);
		return TO_MEMORY_ERROR;
	}
	/* Don't let the status uninitialized in case of read error */
	TO_io_buffer[2] = 0;
	/* Recieve response */
	status = _read_response(data_len);
	FPRINTF(stdout, "%s read:\n", __func__);
	HEX_DISP(TO_io_buffer, data_len);
	/* If read error, it may have occured after status transmission */
	*resp_status = TO_io_buffer[2];
	if (TO_OK != status) {
		FPRINTF(stderr, "%s(cmd=%04X) read error %04X\n",
				__func__, cmd, status);
		if (TO_MEMORY_ERROR == status)
			return TO_MEMORY_ERROR;
		else
			return TO_DEVICE_READ_ERROR;
	}
	_resp_data_len = (uint16_t*)TO_io_buffer;
	*resp_data_len = be16toh(*_resp_data_len);
	/* On command success, check size validity */
	if (*resp_status == TORSP_SUCCESS
			&& *resp_data_len > data_len - TO_RSPHEAD_SIZE) {
		FPRINTF(stderr, "%s(cmd=%04X) read error, response length "
				"(%uB) overflows buffer (%luB)\n",
				__func__, cmd,
				*resp_data_len, data_len - TO_RSPHEAD_SIZE);
		return TO_INVALID_RESPONSE_LENGTH;
	}

	if (_post_command_hook)
		_post_command_hook(cmd, cmd_data_len,
				*resp_data_len, *resp_status);

	return TO_OK;
}

int TO_send_command(const uint16_t cmd, uint16_t cmd_data_len,
		uint16_t *resp_data_len, uint8_t *resp_status)
{
	int ret;
	int renew_retries = 0;
	ret = _send_command(cmd, cmd_data_len, resp_data_len, resp_status);
	/* Secure link requests keys renewal ? */
	if (ret != TO_OK && *resp_status == TORSP_SECLINK_RENEW_KEY) {
		/* Renew the keys and redo the command */
		while (TO_seclink_renew_keys() == TO_SECLINK_ERROR) {
			/* Retrying, just in case a communication error occured
			 * while getting the new key */
			FPRINTF(stderr, "%s: retry secure link key renewal\n",
					__func__);
			if (++renew_retries >= 3) {
				FPRINTF(stderr, "%s: secure link key renewal "
						"failed %d retries, abort",
						__func__, renew_retries);
				return TO_SECLINK_ERROR;
			}
		}
		ret = _send_command(cmd, cmd_data_len,
				resp_data_len, resp_status);
	} else if (ret != TO_OK) {
		/* Any communication error, maybe secure link state data are
		 * desynchronised between libTO and SE, then force secure link
		 * initialisation next time to resynchronise. */
		_seclink_ready = 0;
	}
	TO_reset_command_data();
	return ret;
}

void TO_set_lib_hook_pre_command(TO_pre_command_hook hook)
{
	_pre_command_hook = hook;
}

void TO_set_lib_hook_post_write(TO_post_write_hook hook)
{
	_post_write_hook = hook;
}

void TO_set_lib_hook_post_command(TO_post_command_hook hook)
{
	_post_command_hook = hook;
}
