/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2017 Trusted Objects. All rights reserved.
 */

/**
 * @file seclink_none.c
 * @brief Empty secure link implementation.
 *
 * This implementation doesn't do anything, if used it means no security is
 * added to Secure Element commands and responses.
 */

#include <TO_defs.h>

#if !defined(ENABLE_SECLINK_ARC4) && !defined(ENABLE_SECLINK_AESHMAC)

uint16_t TO_seclink_compute_cmd_size(uint16_t encaps_len)
{
	return encaps_len;
}

uint16_t TO_seclink_compute_rsp_size(uint16_t encaps_len)
{
	return encaps_len;
}

int TO_seclink_init(void)
{
	return TO_OK;
}

int TO_seclink_renew_keys(void)
{
	return TO_OK;
}

int TO_seclink_secure(uint8_t *io_buffer, uint16_t len)
{
	(void)io_buffer;
	(void)len;
	return TO_OK;
}

int TO_seclink_unsecure(uint8_t *io_buffer)
{
	(void)io_buffer;
	return TO_OK;
}

#endif // !ENABLE_SECLINK_ARC4 && !ENABLE_SECLINK_AESHMAC
