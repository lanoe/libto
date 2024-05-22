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
 * @file TO_helper.h
 * @brief Secure Element helpers.
 */

#ifndef _TO_HELPER_H_
#define _TO_HELPER_H_

#ifndef TO_HELPER
#ifdef __linux__
#define TO_HELPER
#elif _WIN32
#define TO_HELPER __declspec(dllexport)
#else
#define TO_HELPER
#endif /* __LINUX__ */
#endif

#include <TO_stdint.h>
#include <stdlib.h>
#include <TO_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ECIES sequence (1st step):
 * authenticate Secure Element
 * @param certificate_index Index of the Secure Element certificate to use
 * @param challenge Challenge (randomly generated) to be provided to the Secure
 * Element
 * @param TO_certificate Short certificate returned by Secure Element
 * @param challenge_signature Signature of the challenge by Secure Element
 *
 * This is the ECIES sequence first step, which aims to authenticate Secure
 * Element.
 * It provides a challenge to Secure Element, and get back its certificate and
 * the challenge signed using the private key associated to the certificate.
 *
 * Refer to Secure Element Datasheet Application Notes - Authenticate Secure
 * Element (and also optimized scheme).
 *
 * Before call you need to:
 * - randomly generate a challenge
 * After call you need to:
 * - check return value (see below)
 * - verify Secure Element certificate signature using CA public key
 * - verify challenge signature using Secure Element certificate public key
 * if previous steps are validated, continue with the next ECIES step:
 * TO_helper_ecies_seq_auth_remote_1() to authenticate the remote device.
 *
 * @return TO_OK if this step is passed successfully.
 */
TO_HELPER int TO_helper_ecies_seq_auth_TO(uint8_t certificate_index,
		uint8_t challenge[TO_CHALLENGE_SIZE],
		uint8_t TO_certificate[sizeof(TO_cert_short_t)],
		uint8_t challenge_signature[TO_SIGNATURE_SIZE]);

/**
 * @brief ECIES sequence (2nd step):
 * authenticate remote device against Secure Element (part 1)
 * @param ca_pubkey_index Index of Certificate Authority public key
 * @param remote_certificate Remote device standalone certificate
 * @param challenge Challenge returned by Secure Element to authenticate remote
 * device
 *
 * This is the ECIES sequence second step, which aims to authenticate remote
 * device (server or other connected object).
 * This first part provides remote device certificate to Secure Element, and
 * get back a random challenge which is going to be used later to authenticate
 * remote device.
 *
 * There is only one remote certificate at a time. If several shared keys are
 * needed, we can overwrite remote certificate after shared keys computing.
 *
 * Refer to Secure Element Datasheet Application Notes - Authenticate Remote
 * Device.
 *
 * Before call you need to:
 * - have completed previous ECIES sequence steps
 * - have the remote device certificate
 * After call you need to:
 * - check return value (see below)
 * - sign the returned challenge using the remote device certificate private key
 * if previous steps are validated, continue with
 * TO_helper_ecies_seq_auth_remote_2() to finalize remote device
 * authentication.
 *
 * @return TO_OK if this step is passed successfully, else:
 * - TORSP_BAD_SIGNATURE: the remote device certificate CA signature is
 *   invalid
 */
TO_HELPER int TO_helper_ecies_seq_auth_remote_1(uint8_t ca_pubkey_index,
		uint8_t remote_certificate[sizeof(TO_cert_standalone_t)],
		uint8_t challenge[TO_CHALLENGE_SIZE]);

/**
 * @brief ECIES sequence (2nd step):
 * authenticate remote
 * device against Secure Element (part 2)
 * @param challenge_signature Challenge signed using remote device certificate
 * private key
 *
 * This is the ECIES sequence second step, which aims to authenticate remote
 * device (server or other connected object).
 * This second part provides challenge signed using remote device certificate
 * private key.
 *
 * Refer to Secure Element Datasheet Application Notes - Authenticate Remote
 * Device.
 *
 * Before call you need to:
 * - have completed previous ECIES sequence steps
 * - compute the challenge signature
 * After call you need to:
 * - check return value (see below)
 * if previous steps are validated, continue with
 * TO_helper_ecies_seq_secure_messaging().
 *
 * @return TO_OK if this step is passed successfully, else:
 * - TORSP_BAD_SIGNATURE: the challenge signature is invalid
 */
TO_HELPER int TO_helper_ecies_seq_auth_remote_2(
		uint8_t challenge_signature[TO_SIGNATURE_SIZE]);

/**
 * @brief ECIES sequence (3rd step):
 * prepare secure data exchange.
 * @param remote_pubkey_index Index where the public key will be stored
 * @param ecc_keypair_index Index of the ECC key pair to renew
 * @param remote_eph_pubkey Remote device ephemeral public key
 * @param remote_eph_pubkey_signature Remote device ephemeral public key
 * signature
 * @param TO_eph_pubkey Returned Secure Element ephemeral public key
 * @param TO_eph_pubkey_signature Secure Element ephemeral public key signature
 *
 * This is the ECIES sequence third step, which aims to prepare secure
 * messaging. Server and connected object will be able to securely exchange
 * data.
 * It provides remote device ephemeral public key signed using remote device
 * certificate private key, and get back Secure Element ephemeral public key.
 *
 * Secure Element public keys, AES keys, and HMAC keys have the same index to
 * use them from Secure Element APIs.
 *
 * Refer to Secure Element Datasheet Application Notes - Secure Messaging.
 *
 * Before call you need to:
 * - have completed previous ECIES sequence steps
 * - generate ephemeral key pair
 * - sign the ephemeral public key using remote device certificate private key
 * After call you need to:
 * - check return value (see below)
 * - check Secure Element ephemeral public key signature using Secure Element
 *   certificate public key
 * - compute shared secret using remote device and Secure Element ephemeral
 *   public keys
 * - derive shared secret with SHA256 to get AES and HMAC keys
 * 
 * If previous steps are validated, AES and HMAC keys can be used for secure
 * messaging.
 *
 * @return TO_OK if this step is passed successfully, else:
 * - TORSP_BAD_SIGNATURE: the remote device public key signature is invalid
 */
TO_HELPER int TO_helper_ecies_seq_secure_messaging(
		uint8_t remote_pubkey_index, uint8_t ecc_keypair_index,
		uint8_t remote_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t remote_eph_pubkey_signature[TO_SIGNATURE_SIZE],
		uint8_t TO_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t TO_eph_pubkey_signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Handle TLS Server Certificate at once
 * @param server_certificate Certificate payload
 * @param server_certificate_len Certificate payload length
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
TO_HELPER int TO_helper_tls_handle_server_certificate(
		const uint8_t *server_certificate,
		const uint32_t server_certificate_len);

/**
 * @brief Get TLS Certificate at once
 * @param certificate Certificate payload
 * @param certificate_len Certificate payload length
 *
 * @return TO_OK if data has been received successfully, else TO_ERROR
 */
TO_HELPER int TO_helper_tls_get_certificate(
		uint8_t *certificate,
		uint16_t *certificate_len);

/**
 * @brief Handshake helper network send function.
 * @param ctx Opaque context given to "TO_helper_tls_handshake"
 * @param data Data to send
 * @param len Length of data
 *
 * This function is used by "TO_helper_tls_handshake" to send data on the
 * network.
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
typedef int (*TO_helper_tls_handshake_send_func)(void *ctx,
		const uint8_t *data, const uint32_t len);

/**
 * @brief Handshake helper network receive function.
 * @param ctx Opaque context given to "TO_helper_tls_handshake"
 * @param data Data output
 * @param len Length of data to read
 * @param read_len Length of data read
 * @param timeout Receive timeout in milliseconds (-1 for no timeout)
 *
 * This function is used by "TO_helper_tls_handshake" to receive data from
 * the network.
 *
 * @return TO_OK if data has been sent successfully, else:
 * - TO_TIMEOUT: Receive timed out
 * - TO_ERROR: Other error
 */
typedef int (*TO_helper_tls_handshake_receive_func)(void *ctx, uint8_t *data,
		const uint32_t len, uint32_t *read_len, int32_t timeout);

/**
 * @brief Initialize TLS handshake
 *
 * This function initialize TLS handshake.
 * It configures the Secure Element and initialize static envrionment.
 *
 * @return TO_OK if initialization succeed, else TO_ERROR
 */
TO_HELPER int TO_helper_tls_handshake_init(void);

/**
 * @brief Do TLS handshake step
 * @param ctx Opaque context to forward to given functions
 * @param send_func Function to send on network
 * @param receive_func Function to receive from network
 *
 * This function does one step of a TLS handshake.
 * It encapsulates TO payloads from optimized API in a TLS record, and send
 * it on the network through given function.
 * It decapsulates TLS records received from the network and send it to TO.
 *
 * @return TO_AGAIN if intermediate step suceed, TO_OK if last step succeed,
 * else TO_ERROR
 */
TO_HELPER int TO_helper_tls_handshake_step(void *ctx,
		TO_helper_tls_handshake_send_func send_func,
		TO_helper_tls_handshake_receive_func receive_func);

/**
 * @brief Do TLS handshake
 * @param ctx Opaque context to forward to given functions
 * @param send_func Function to send on network
 * @param receive_func Function to receive from network
 *
 * This function does all the steps of a TLS handshake.
 * It encapsulates TO payloads from optimized API in a TLS record, and send
 * it on the network through given function.
 * It decapsulates TLS records received from the network and send it to TO.
 * This function uses `TO_helper_tls_handshake_init` and
 * `TO_helper_tls_handshake_step`.
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
TO_HELPER int TO_helper_tls_handshake(void *ctx,
		TO_helper_tls_handshake_send_func send_func,
		TO_helper_tls_handshake_receive_func receive_func);

/**
 * @brief Send TLS encrypted message
 * @param msg Message
 * @param msg_len Message length
 * @param ctx Opaque context to forward to given functions
 * @param send_func Function to send on network
 *
 * This function uses TLS handshake keys to encrypt and send a message on the
 * network through given function.
 *
 * @return TO_OK if message has been sent successfully, else TO_ERROR
 */
TO_HELPER int TO_helper_tls_send_message(uint8_t *msg, uint32_t msg_len,
		void *ctx, TO_helper_tls_handshake_send_func send_func);

/**
 * @brief Receive TLS encrypted message
 * @param msg Message output buffer
 * @param max_msg_len Message output buffer length
 * @param msg_len Receive message length
 * @param ctx Opaque context to forward to given functions
 * @param receive_func Function to receive from network
 *
 * This function uses given function to receive a message from the network and
 * decrypts it with TLS handshake keys. *
 *
 * @return TO_OK if message has been sent successfully, else TO_ERROR
 */
TO_HELPER int TO_helper_tls_receive_message(uint8_t *msg,
		uint32_t max_msg_len, uint32_t *msg_len,
		void *ctx, TO_helper_tls_handshake_receive_func receive_func);

/**
 * @brief Receive TLS encrypted message with timeout
 * @param msg Message output buffer
 * @param max_msg_len Message output buffer length
 * @param msg_len Receive message length
 * @param timeout Receive timeout in milliseconds (-1 for no timeout)
 * @param ctx Opaque context to forward to given functions
 * @param receive_func Function to receive from network
 *
 * This function uses given function to receive a message from the network and
 * decrypts it with TLS handshake keys. *
 *
 * @return TO_OK if message has been received successfully, TO_TIMEOUT if
 * given timeout has been exceeded, else TO_ERROR
 */
TO_HELPER int TO_helper_tls_receive_message_with_timeout(uint8_t *msg,
		uint32_t max_msg_len, uint32_t *msg_len, int32_t timeout,
		void *ctx, TO_helper_tls_handshake_receive_func receive_func);

/**
 * @brief Secure message with TLS
 * @param header TLS header
 * @param data TLS data
 * @param data_len TLS data length
 * @param initial_vector Initial vector used to encrypt
 * @param cryptogram Securized message (without header)
 * @param cryptogram_len Securized message (without header) length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_HELPER int TO_helper_tls_secure_message(
		const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t* data, const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram, uint16_t *cryptogram_len);

/**
 * @brief Unsecure message with TLS
 * @param header TLS header
 * @param initial_vector Initial vector used to encrypt
 * @param cryptogram Securized message (without header)
 * @param cryptogram_len Securized message (without header) length
 * @param data TLS data
 * @param data_len TLS data length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_HELPER int TO_helper_tls_unsecure_message(const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len);

/**
 * @brief Handle certificate chain at once
 * @param ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 * @param chain_certificate Certificate chain
 * @param chain_certificate_length Certificate chain length
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Final certificate
 * - Intermediate CA certificates (if any)
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Each certificate must be signed by the next.
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
TO_HELPER int TO_helper_verify_chain_certificate_and_store(
		const uint8_t ca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

/**
 * @brief Handle CA certificate chain at once
 * @param ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 * @param subca_key_index subCA index to store subCA
 * @param chain_certificate Certificate chain
 * @param chain_certificate_length Certificate chain length
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Intermediate CA certificates
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Each certificate must be signed by the next.
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
TO_HELPER int TO_helper_verify_chain_ca_certificate_and_store(
		const uint8_t ca_key_index,
		const uint8_t subca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

#ifdef __cplusplus
}
#endif

#endif
