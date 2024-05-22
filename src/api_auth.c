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
 * @file api_auth.c
 * @brief Secure Element authentication functions (signatures, certificates).
 */

#include <core.h>

#ifndef TO_DISABLE_CERT_MGMT
#ifndef TO_DISABLE_API_GET_CERTIFICATE_SUBJECT_CN
int TO_get_certificate_subject_cn(const uint8_t certificate_index,
		char subject_cn[TO_CERT_SUBJECT_CN_MAXSIZE + 1])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_CERT_SUBJECT_CN_MAXSIZE;

	ret = TO_prepare_command_data_byte(0, certificate_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_CERTIFICATE_SUBJECT_CN, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len > TO_CERT_SUBJECT_CN_MAXSIZE)
		return TORSP_INVALID_LEN;

	secure_memcpy(subject_cn, TO_response_data, resp_data_len);
	subject_cn[resp_data_len] = '\0';
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE
int TO_get_certificate(const uint8_t certificate_index,
		const TO_certificate_format_t format, uint8_t* certificate)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len;

	switch (format) {
	case TO_CERTIFICATE_STANDALONE:
		resp_data_len = sizeof(TO_cert_standalone_t);
		break;
	case TO_CERTIFICATE_SHORT:
		resp_data_len = sizeof(TO_cert_short_t);
		break;
	case TO_CERTIFICATE_X509:
	default:
		FPRINTF(stderr, "unsupported certificate format 0x%02X\n",
				format);
		return TO_INVALID_CERTIFICATE_FORMAT;
	}

	ret = TO_prepare_command_data_byte(0, certificate_index);
	ret |= TO_prepare_command_data_byte(1, format & 0xFF);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_CERTIFICATE, 2,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(certificate, TO_response_data, resp_data_len);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_X509
TO_API int TO_get_certificate_x509(const uint8_t certificate_index,
		uint8_t* certificate, uint16_t* size)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len;

	resp_data_len = TO_MAXSIZE;
	ret = TO_prepare_command_data_byte(0, certificate_index);
	ret |= TO_prepare_command_data_byte(1, TOCERTF_X509);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_CERTIFICATE, 2,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(certificate, TO_response_data, resp_data_len);
	*size = resp_data_len;
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_AND_SIGN
int TO_get_certificate_and_sign(const uint8_t certificate_index,
		const TO_certificate_format_t format,
		uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint8_t* signature)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = challenge_length + 2;
	uint16_t resp_data_len;

	switch (format) {
	case TO_CERTIFICATE_STANDALONE:
		resp_data_len = sizeof(TO_cert_standalone_t);
	break;
	case TO_CERTIFICATE_SHORT:
		resp_data_len = sizeof(TO_cert_short_t);
	break;
	case TO_CERTIFICATE_X509:
	default:
		FPRINTF(stderr, "unsupported certificate format\n");
		return TO_INVALID_CERTIFICATE_FORMAT;
	}
	resp_data_len += TO_SIGNATURE_SIZE;

	cmd_len = challenge_length + 2;
	ret = TO_prepare_command_data_byte(0, certificate_index);
	ret |= TO_prepare_command_data_byte(1, format & 0xFF);
	ret |= TO_prepare_command_data(2, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_CERTIFICATE_AND_SIGN, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(certificate, TO_response_data, resp_data_len - 64);
	secure_memcpy(signature, TO_response_data + (resp_data_len - 64), 64);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_X509_AND_SIGN
TO_API int TO_get_certificate_x509_and_sign(const uint8_t certificate_index,
		uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint16_t* size, uint8_t* signature)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = challenge_length + 2;
	uint16_t resp_data_len;

	resp_data_len = TO_MAXSIZE;
	resp_data_len += TO_SIGNATURE_SIZE;
	cmd_len = challenge_length + 2;
	ret = TO_prepare_command_data_byte(0, certificate_index);
	ret |= TO_prepare_command_data_byte(1, TOCERTF_X509);
	ret |= TO_prepare_command_data(2, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_GET_CERTIFICATE_AND_SIGN, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(certificate, TO_response_data, resp_data_len - 64);
	*size = resp_data_len - TO_SIGNATURE_SIZE;
	secure_memcpy(signature, TO_response_data + (resp_data_len - 64), 64);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CERTIFICATE_AND_STORE
int TO_verify_certificate_and_store(const uint8_t ca_key_id,
		const TO_certificate_format_t format, uint8_t* certificate)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 2; /* ca_id + format */
	uint16_t cert_size;
	uint16_t resp_data_len = 0;

	switch(format) {
		case TO_CERTIFICATE_STANDALONE:
			cert_size = sizeof(TO_cert_standalone_t);
			break;
		case TO_CERTIFICATE_SHORT:
			cert_size = sizeof(TO_cert_short_t);
			break;
		case TO_CERTIFICATE_SHORT_V2:
			cert_size = sizeof(TO_cert_short_v2_t);
			break;
		case TO_CERTIFICATE_X509: {
			uint8_t len = certificate[1] & 0x7F;
			uint32_t _cert_size = 0;
			secure_memcpy((uint8_t*)(&_cert_size) + sizeof(uint32_t) - len,
					certificate + 2, len);
			cert_size = 2 + len + (uint16_t)be32toh(_cert_size);
			break;
		}
		default:
			FPRINTF(stderr, "unsupported certificate format "
					"0x%02X\n", format);
			return TO_INVALID_CERTIFICATE_FORMAT;
	}
	cmd_len += cert_size;

	ret = TO_prepare_command_data_byte(0, ca_key_id);
	ret |= TO_prepare_command_data_byte(1, format & 0xFF);
	ret |= TO_prepare_command_data(2, certificate, cert_size);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_CERTIFICATE_AND_STORE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CA_CERTIFICATE_AND_STORE
int TO_verify_ca_certificate_and_store(const uint8_t ca_key_index,
		const uint8_t subca_key_index, const uint8_t *certificate,
		const uint16_t certificate_len)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 2 + certificate_len;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, ca_key_index);
	ret |= TO_prepare_command_data_byte(1, subca_key_index);
	ret |= TO_prepare_command_data(2, certificate, certificate_len);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_CA_CERTIFICATE_AND_STORE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CHALLENGE_AND_STORE
int TO_get_challenge_and_store(uint8_t challenge[TO_CHALLENGE_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = TO_CHALLENGE_SIZE;

	ret = TO_send_command(TOCMD_GET_CHALLENGE_AND_STORE, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(challenge, TO_response_data, TO_CHALLENGE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CHALLENGE_SIGNATURE
int TO_verify_challenge_signature(
		const uint8_t signature[TO_SIGNATURE_SIZE])
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	cmd_len = TO_SIGNATURE_SIZE;
	ret = TO_prepare_command_data(0, signature, TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret =  TO_send_command(TOCMD_VERIFY_CHALLENGE_SIGNATURE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CHAIN_CERTIFICATE_AND_STORE
int TO_verify_chain_certificate_and_store_init(
		const uint8_t ca_key_index)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, ca_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_INIT, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_verify_chain_certificate_and_store_update(
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, chain_certificate,
			chain_certificate_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE,
			chain_certificate_length, &resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_verify_chain_certificate_and_store_final(void)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_send_command(TOCMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_FINAL, 0,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE
int TO_verify_chain_ca_certificate_and_store_init(
		const uint8_t ca_key_index, const uint8_t subca_key_index)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, ca_key_index);
	ret |= TO_prepare_command_data_byte(1, subca_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_INIT, 2,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_verify_chain_ca_certificate_and_store_update(
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data(0, chain_certificate,
			chain_certificate_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE,
			chain_certificate_length, &resp_data_len, &resp_status);

	return ret | resp_status;
}

int TO_verify_chain_ca_certificate_and_store_final(void)
{
	int ret;
	uint8_t resp_status;
	uint16_t resp_data_len = 0;

	ret = TO_send_command(TOCMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_FINAL, 0,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_CERT_MGMT

#ifndef TO_DISABLE_SIGNING
#ifndef TO_DISABLE_API_SIGN
int TO_sign(const uint8_t key_index, uint8_t* challenge,
		const uint16_t challenge_length, uint8_t* signature)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = challenge_length + 1;
	uint16_t resp_data_len = TO_SIGNATURE_SIZE;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_SIGN, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(signature, TO_response_data, TO_SIGNATURE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY
int TO_verify(const uint8_t key_index, uint8_t* data,
		const uint16_t data_length, const uint8_t* signature)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 1 + data_length + TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, data, data_length);
	ret |= TO_prepare_command_data(1 + data_length, signature,
			TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_SIGN_HASH
TO_API int TO_sign_hash(const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], uint8_t* signature)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 1 + TO_HASH_SIZE;
	uint16_t resp_data_len = TO_SIGNATURE_SIZE;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, hash, TO_HASH_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_SIGN_HASH, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	secure_memcpy(signature, TO_response_data, TO_SIGNATURE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_HASH_SIGNATURE
TO_API int TO_verify_hash_signature(const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], const uint8_t* signature)
{
	int ret;
	uint8_t resp_status;
	uint16_t cmd_len = 1 + TO_HASH_SIZE + TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	ret = TO_prepare_command_data_byte(0, key_index);
	ret |= TO_prepare_command_data(1, hash, TO_HASH_SIZE);
	ret |= TO_prepare_command_data(1 + TO_HASH_SIZE, signature,
			TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TO_send_command(TOCMD_VERIFY_HASH_SIGNATURE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_SIGNING
