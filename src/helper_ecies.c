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
 * @file helper_ecies.c
 * @brief Secure Element ECIES helper, besed on Secure Element APIs to simplify
 * ECIES sequence.
 */

#include <TO.h>
#include <TO_helper.h>
#include <core.h>

#ifndef TO_DISABLE_ECIES_HELPER

/* Dependency checks */
#ifdef TO_DISABLE_CERT_MGMT
#error Certificates management APIs must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_GET_CERTIFICATE_AND_SIGN
#error TO_get_certificate_and_sign API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_VERIFY_CERTIFICATE_AND_STORE
#error TO_verify_certificate_and_store API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_GET_CHALLENGE_AND_STORE
#error TO_get_challenge_and_store API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_VERIFY_CHALLENGE_SIGNATURE
#error TO_verify_challenge_signature API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_KEYS_MGMT
#error Keys management APIs must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_SET_REMOTE_PUBLIC_KEY
#error TO_set_remote_public_key API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_RENEW_ECC_KEYS
#error TO_renew_ecc_keys API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_RENEW_SHARED_KEYS
#error TO_renew_shared_keys API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_GET_PUBLIC_KEY
#error TO_get_public_key API must be enabled for ECIES helper
#endif

int TO_helper_ecies_seq_auth_TO(uint8_t certificate_index,
		uint8_t challenge[TO_CHALLENGE_SIZE],
		uint8_t TO_certificate[sizeof(TO_cert_short_t)],
		uint8_t challenge_signature[TO_SIGNATURE_SIZE])
{
	int ret;

	ret = TO_get_certificate_and_sign(
			certificate_index, TO_CERTIFICATE_SHORT,
			challenge, TO_CHALLENGE_SIZE,
			TO_certificate, challenge_signature);
	if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to get Secure Element "
				"certificate, error %X\n", ret);
		return TO_ERROR;
	}

	return TO_OK;
}

int TO_helper_ecies_seq_auth_remote_1(uint8_t ca_pubkey_index,
		uint8_t remote_certificate[sizeof(TO_cert_standalone_t)],
		uint8_t challenge[TO_CHALLENGE_SIZE])
{
	int ret;

	ret = TO_verify_certificate_and_store(ca_pubkey_index,
			TO_CERTIFICATE_STANDALONE, remote_certificate);
	if (ret == TORSP_BAD_SIGNATURE) {
		FPRINTF(stderr, "ECIES seq. error: invalid remote certificate "
				"CA signature\n");
		return TORSP_BAD_SIGNATURE;
	} else if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to verify and store "
				"remote certificate, error %X\n", ret);
		return TO_ERROR;
	}
	ret = TO_get_challenge_and_store(challenge);
	if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to get challenge "
				"from TO, error %X\n", ret);
		return TO_ERROR;
	}

	return TO_OK;
}

int TO_helper_ecies_seq_auth_remote_2(
		uint8_t challenge_signature[TO_SIGNATURE_SIZE])
{
	int ret;

	ret = TO_verify_challenge_signature(challenge_signature);
	if (ret == TORSP_BAD_SIGNATURE) {
		FPRINTF(stderr, "ECIES seq. error: bad challenge signature\n");
		return TORSP_BAD_SIGNATURE;
	} else if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to verify challenge "
				"signature, error %X\n", ret);
		return TO_ERROR;
	}

	return TO_OK;
}

int TO_helper_ecies_seq_secure_messaging(
		uint8_t remote_pubkey_index, uint8_t ecc_keypair_index,
		uint8_t remote_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t remote_eph_pubkey_signature[TO_SIGNATURE_SIZE],
		uint8_t TO_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t TO_eph_pubkey_signature[TO_SIGNATURE_SIZE])
{
	int ret;

	ret = TO_set_remote_public_key(remote_pubkey_index,
			remote_eph_pubkey, remote_eph_pubkey_signature);
	if (ret == TORSP_BAD_SIGNATURE) {
		FPRINTF(stderr, "ECIES seq. error: bad remote public key "
			       "signature\n");
		return TORSP_BAD_SIGNATURE;
	} else if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to set remote public "
				"key, error %X\n", ret);
		return TO_ERROR;
	}
	ret = TO_renew_ecc_keys(ecc_keypair_index);
	if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to renew ECC keys, "
				"error %X\n", ret);
		return TO_ERROR;
	}
	ret = TO_get_public_key(ecc_keypair_index, TO_eph_pubkey,
			TO_eph_pubkey_signature);
	if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to get Secure Element public "
				"key, error %X\n", ret);
		return TO_ERROR;
	}
	ret = TO_renew_shared_keys(ecc_keypair_index, remote_pubkey_index);
	if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "ECIES seq. error: unable to renew shared "
				"keys, key, error %X\n", ret);
		return TO_ERROR;
	}

	return TO_OK;
}

#endif // TO_DISABLE_ECIES_HELPER
