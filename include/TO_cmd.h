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
 * @file TO_cmd.h
 * @brief TO library commands API, to abstract Secure Element commands
 * protocol.
 *
 * Following APIs are based on libTO internal I/O buffers and mechanisms, to
 * prepare a new command data, send the command, and revieve the response or
 * error.
 */

#ifndef _TO_CMD_H_
#define _TO_CMD_H_

#include <TO_stdint.h>
#include <TO_defs.h>

#ifndef TO_CMDAPI
#ifdef __linux__
#define TO_CMDAPI
#elif _WIN32
#define TO_CMDAPI __declspec(dllexport)
#else
#define TO_CMDAPI
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper to access internal I/O buffer command data section, only valid before
 * TO_send_command() call (even if an error occured while sending command).
 */
TO_CMDAPI extern unsigned char *TO_command_data;

/**
 * Helper to access internal I/O buffer response data section, only valid after
 * TO_send_command() call.
 */
TO_CMDAPI extern unsigned char *TO_response_data;

/**
 * @brief Reset command data.
 *
 * This function resets command data.
 * It MUST be called if command data has been prepared without subsequent call
 * to TO_send_command() (if command has been aborted for example).
 */
TO_CMDAPI void TO_reset_command_data(void);

/**
 * @brief Prepare command data.
 * @param offset Buffer offset where to insert data
 * @param data Data to be copied into the buffer
 * @param len Data length
 *
 * Insert data into the internal I/O buffer at the specified offset.
 *
 * Warning: do not free data pointer parameter or overwrite data before having
 * called TO_send_command(), or before aborted command with
 * TO_reset_command_data().
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: data overflows internal I/O buffer, in this case internal
 * command data buffers are invalidated (as if TO_reset_command_data() has been
 * called).
 */
TO_CMDAPI int TO_prepare_command_data(uint16_t offset,
		const unsigned char *data, uint16_t len);

/**
 * @brief Prepare command data byte.
 * @param offset Buffer offset where to insert data
 * @param byte Data byte to be copied into the buffer
 *
 * Insert data byte into the internal I/O buffer at the specified offset.
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: data byte overflows internal I/O buffer, in this case
 * internal command data buffers are invalidated (as if TO_reset_command_data()
 * has been called).
 */
TO_CMDAPI int TO_prepare_command_data_byte(uint16_t offset,
		const char byte);

/**
 * @brief Set data range.
 * @param offset Buffer offset where to begin range
 * @param byte Value to be set for each byte in the range
 * @param len Range length
 *
 * Set internal I/O buffer range bytes to a defined value.
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: range overflows internal I/O buffer, in this case internal
 * command data buffers are invalidated (as if TO_reset_command_data() has been
 * called).
 */
TO_CMDAPI int TO_set_command_data(uint16_t offset, const char byte,
		uint16_t len);

/**
 * @brief Send command to the Secure Element device.
 * @param cmd Command code (see TOCMD_* definitions)
 * @param cmd_data_len Command data len (got from internal I/O buffer)
 * @param resp_data_len Response data len (expected)
 * @param resp_status Status of the command
 *
 * Send a command to the Secure Element device and get response data.
 * Internal command data buffers must be considered as invalidated after
 * calling this function.
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: data overflows internal I/O buffer
 * TO_DEVICE_WRITE_ERROR: unable to send command
 * TO_DEVICE_READ_ERROR: unable to read response data
 * TO_INVALID_RESPONSE_LENGTH: expected response length differs from headers
 */
TO_CMDAPI int TO_send_command(const uint16_t cmd, uint16_t cmd_data_len,
		uint16_t* resp_data_len, uint8_t* resp_status);


/** @addtogroup libhooks
 * @{ */

/**
 * @brief Hook function prototype to be called by TO_send_command() just before
 * sending a command to the Secure Element.
 * @param cmd Command code, see @ref cmdcodes
 * @param cmd_data_len Command data length
 *
 * Once return, the command response is read from Secure Element.
 *
 * Warning: do NOT call any libTO function from this kind of hook.
 */
typedef void (*TO_pre_command_hook)(uint16_t cmd, uint16_t cmd_data_len);

/**
 * @brief Hook function prototype to be called by TO_send_command() just after
 * writing command to the Secure Element, and before reading its response.
 * @param cmd Command code, see @ref cmdcodes
 * @param cmd_data_len Command data length
 *
 * This hook can be used by client application for power optimization, for
 * example making the system sleep for a while or until Secure Element status
 * GPIO signals response readyness. For this second use case, it is recommended
 * to arm GPIO wakeup interrupt by setting a hook with TO_pre_command_hook(),
 * to be sure to do not miss the response readyness GPIO toggle.
 *
 * Once return, the command response is read from Secure Element.
 *
 * Warning: do NOT call any libTO function from this kind of hook.
 */
typedef void (*TO_post_write_hook)(uint16_t cmd, uint16_t cmd_data_len);

/**
 * @brief Hook function prototype to be called by TO_send_command() just after
 * reading command response from the Secure Element.
 * @param cmd Command code, see @ref cmdcodes
 * @param cmd_data_len Command data length
 * @param cmd_rsp_len Command response length
 * @param cmd_status Command status
 *
 * Warning: do NOT call any libTO function from this kind of hook.
 */
typedef void (*TO_post_command_hook)(uint16_t cmd, uint16_t cmd_data_len,
		uint16_t cmd_rsp_len, uint8_t cmd_status);

/**
 * @brief Set a pre command hook (see TO_pre_command_hook).
 * @param hook Pre command hook function to set (NULL to disable).
 */
TO_CMDAPI void TO_set_lib_hook_pre_command(TO_pre_command_hook hook);

/**
 * @brief Set a post write hook (see TO_post_write_hook).
 * @param hook Post write hook function to set (NULL to disable).
 */
TO_CMDAPI void TO_set_lib_hook_post_write(TO_post_write_hook hook);

/**
 * @brief Set a post cmd hook (see TO_post_command_hook).
 * @param hook Post cmd hook function to set (NULL to disable).
 */
TO_CMDAPI void TO_set_lib_hook_post_command(TO_post_command_hook hook);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
