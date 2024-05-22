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
 * @file seclink.h
 * @brief Secure link API, to be able to use Secure Element secure link.
 *
 * For every new secure link protocol to support, this API has to be
 * implemented.
 */

#ifndef _TO_SECLINK_H_

#ifndef TO_SECLINK
#ifdef __linux__
#define TO_SECLINK
#elif _WIN32
#define TO_SECLINK __declspec(dllexport)
#else
#define TO_SECLINK
#endif /* __LINUX__ */
#endif

#include <TO.h>

/*
 * Keys management callbacks used by secure link implementations.
 */
extern TO_seclink_store_keys_cb _seclink_store_keys_cb_p;
extern TO_seclink_load_keys_cb _seclink_load_keys_cb_p;

/**
 * seclink_init() - Initializes secure link
 *
 * Return: TO_OK on success
 */
int TO_seclink_init(void);

/**
 * TO_seclink_renew_key() - Renew Secure Link keys
 * The new keys are returned through the TO_seclink_store_keys_cb() callback
 * function.
 *
 * Return: TO_OK on success
 */
int TO_seclink_renew_keys(void);

/**
 * TO_seclink_secure() - Secure link command encapsulation
 * @io_buffer: Buffer containing command headers and data
 * @len: Command headers and data length
 *
 * Note: for this function implementation, take care about integers endianness
 * when building secure frame.
 *
 * Return: TO_OK on success
 */
int TO_seclink_secure(uint8_t *io_buffer, uint16_t len);

/**
 * TO_seclink_unsecure() - Ssecure link response decapsulation
 * @io_buffer: Buffer containing response headers and data
 *
 * Note: for this function implementation, take care about integers endianness
 * when building secure frame.
 *
 * Return: TO_OK on success, else:
 *	TO_SECLINK_ERROR | TORSP_* on unsecurisation error
 *	TO_INVALID_RESPONSE_LENGTH if the encapsulated response is less than
 *	response headers length
 */
int TO_seclink_unsecure(uint8_t *io_buffer);

/**
 * TO_seclink_compute_cmd_size() - Compute secure link size
 * @encaps_len: Encapsulated command length
 *
 * Additional bytes are used by secure link encapsulation.
 * This function returns the expected full length of a secure link, given
 * the encapsulated command length (header + data).
 * This function should not take care about length overflow.
 *
 * Return: secure link length
 */
uint16_t TO_seclink_compute_cmd_size(uint16_t encaps_len);

/**
 * TO_seclink_compute_rsp_size() - Compute secure link response size
 * @encaps_len: Encapsulated response length
 *
 * Additional bytes are used by secure link response encapsulation.
 * This function returns the expected full length of a secure link response,
 * given the encapsulated response length (header + data).
 * This function should not take care about length overflow.
 *
 * Return: secure link response length
 */
uint16_t TO_seclink_compute_rsp_size(uint16_t encaps_len);

#endif
