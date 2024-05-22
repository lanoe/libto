/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2018 Trusted Objects. All rights reserved.
 */

/**
 * @file helper_certs.c
 * @brief Secure Element certificates helper, based on Secure Element APIs to
 * simplify commands sequences.
 */

#include <TO.h>
#include <TO_helper.h>
#include <core.h>

#ifndef TO_DISABLE_CERTS_HELPER

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define _VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE_SIZE 512

int TO_helper_verify_chain_certificate_and_store(
		const uint8_t ca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	uint32_t offset = 0;
	int ret;

	ret = TO_verify_chain_certificate_and_store_init(ca_key_index);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	while (offset < chain_certificate_length) {
		uint32_t len = MIN(_VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE_SIZE,
				chain_certificate_length- offset);
		ret = TO_verify_chain_certificate_and_store_update(
				chain_certificate + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR;
		}
		offset += len;
	}

	ret = TO_verify_chain_certificate_and_store_final();
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	return TO_OK;
}

#define _VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE_SIZE 512

int TO_helper_verify_chain_ca_certificate_and_store(
		const uint8_t ca_key_index,
		const uint8_t subca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	uint32_t offset = 0;
	int ret;

	ret = TO_verify_chain_ca_certificate_and_store_init(ca_key_index,
			subca_key_index);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	while (offset < chain_certificate_length) {
		uint32_t len = MIN(_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE_SIZE,
				chain_certificate_length - offset);
		ret = TO_verify_chain_ca_certificate_and_store_update(
				chain_certificate + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR;
		}
		offset += len;
	}

	ret = TO_verify_chain_ca_certificate_and_store_final();
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	return TO_OK;
}

#endif // TO_DISABLE_CERTS_HELPER
