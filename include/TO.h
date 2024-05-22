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
 * @file TO.h
 * @brief Functions provided by libTO to deal with it and send commands to
 * Secure Element.
 */

#ifndef _TO_H_
#define _TO_H_

#include <TO_stdint.h>
#include <TO_defs.h>
#include <TO_cfg.h>

#ifndef TO_API
#ifdef __linux__
#define TO_API
#elif _WIN32
#define TO_API __declspec(dllexport)
#else
#define TO_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup i2csetup
 * @{ */

/**
 * @brief Initialize Secure Element communication.
 *
 * If endianness is not explicitely defined through project settings macros,
 * this function performs an automatic endianness detection.
 *
 * @return TO_OK if initialization was successful.
 */
TO_API int TO_init(void);

/**
 * @brief Finish Secure Element communication.
 * @return TO_OK if finalization was successful.
 */
TO_API int TO_fini(void);

/**
 * @brief Configure Secure Element communication.
 * @param i2c_addr I2C address to use
 * @param misc_settings Misc. settings byte. It have the following bit form
 * (from MSB to LSB): RES, RES, RES, RES, RES, RES, RES, last byte NACKed.
 * The *last byte NACKed* bit must be set to 1 if remote device NACKs last
 * written byte.
 *
 * See TO_data_config() for more details.
 *
 * @return TO_OK if configuration was successful.
 */
TO_API int TO_config(unsigned char i2c_addr, unsigned char misc_settings);

/** @} */

/** @addtogroup i2crw
 * @{ */

/**
 * @brief Write data to Secure Element
 * @param data Buffer containing data to send
 * @param length Amount of data to send in bytes
 *
 * This function uses the underlying TO_data_write() wrapper function. Refer
 * to its documentation for more details.
 *
 * @return
 * - TO_OK if data has been written sucessfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_ERROR if an internal error has occured
 */
TO_API int TO_write(const void *data, unsigned int length);

/**
 * @brief Read data from Secure Element
 * @param data Buffer to store recieved data
 * @param length Amount of data to read in bytes
 *
 * This function uses the underlying TO_data_read() wrapper function. Refer
 * to its documentation for more details.
 *
 * @return
 * - TO_OK if data has been read sucessfully
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR if an internal error has occured
 */
TO_API int TO_read(void *data, unsigned int length);

/**
 * @brief Last command duration from Secure Element
 * @param duration Pointer to store last command duration in microseconds
 *
 * This function uses the underlying TO_data_last_command_duration() wrapper
 * function. Refer to its documentation for more details.
 *
 * This function should only be called after a successful command or a
 * successful TO_read() call.
 * If it is called after a failed command or a failed TO_read(), or after a
 * TO_write() call, the result is unspecified and may be irrelevant.
 *
 * @return
 * - TO_OK if data has been read sucessfully
 * - TO_ERROR if an internal error has occured
 */
TO_API int TO_last_command_duration(unsigned int *duration);

/** @} */

/** @addtogroup system
 * @{ */

/**
 * @brief Returns the unique Secure Element Serial Number
 * @param serial_number Returned device serial number
 *
 * Serial Number data are encoded on 8 bytes. The first 3 bytes identify
 * Certificate Authority (CA), or the Factory if CA is not relevant. The last 5
 * bytes are the chip ID. Each Secure Element has an unique serial number.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_serial_number(uint8_t serial_number[TO_SN_SIZE]);

/**
 * @brief Returns the Product Number of the TO
 * @param product_number Returned device product number
 *
 * Product Number is a text string encoded on 12 bytes, e.g:
 * "TOSF-IS1-001"
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_product_number(uint8_t product_number[TO_PN_SIZE]);

/**
 * @brief Returns the Hardware Version of the TO
 * @param hardware_version Returned device hardware version
 *
 * Hardware version is encoded on 2 bytes. Available values are:
 * - 00: reserved
 * - 01: SCB136i
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_hardware_version(
		uint8_t hardware_version[TO_HW_VERSION_SIZE]);

/**
 * @brief Returns the Software Version of the TO
 * @param major Major number
 * @param minor Minor number
 * @param revision Revision number
 *
 * Software version major number is incremented on API change, minor number is
 * incremented when there are changes in features without breaking the API,
 * revision number is incremented for each new build (without major change, and
 * with no API break).
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_software_version(uint8_t* major, uint8_t* minor,
		uint8_t* revision);

/**
 * @brief Returns a random number of the given length
 * @param random_length Requested random length
 * @param random Returned random number
 *
 * Request a random number to Secure Element random number generator.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: random length out of range
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_random(const uint16_t random_length, uint8_t* random);

/** @} */

/** @addtogroup statuspio
 * @{ */

/**
 * @brief Configure Secure Element status PIO notification behavior.
 * @param enable Set to 1 to enable status PIO notifications (default: 1)
 * @param opendrain Set to 1 for open drain, 0 for push pull (default: 1)
 * @param ready_level Set to 1 to signal readyness with high PIO level, 0 to
 * signal it with low PIO level (default: 1).
 * @param idle_hz Set to 1 to have idle state signalled by PIO high impedance
 * signal it with a low level (default: 1)
 *
 * The configuration is stored permanently by the Secure Element, and then
 * persists across reboots.
 *
 * Note: this function do not have BUSY / READY states, the PIO remains in the
 * IDLE state when called. But if the pushed settings change the PIO levels or
 * signalling method, the PIO state can change when this function is called.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_ERROR: generic error
 */
TO_API int TO_set_status_PIO_config(int enable,
		int opendrain, int ready_level, int idle_hz);

/**
 * @brief Return Secure Element status PIO notification configuration.
 * @param enable Set to 1 if status PIO notification enabled
 * @param opendrain Method to signal level, see TO_set_status_PIO_config()
 * @param ready_level PIO level to signal ready state, see
 * TO_set_status_PIO_config()
 * @param idle_hz Idle state signalled by PIO high impedance, see
 * TO_set_status_PIO_config()
 *
 * Note: this function do not have BUSY / READY states, the PIO remains in the
 * IDLE state when called.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_ERROR: generic error
 */
TO_API int TO_get_status_PIO_config(int *enable,
		int *opendrain, int *ready_level, int *idle_hz);

/** @} */

/** @addtogroup hashes
 * @{ */

/**
 * @brief SHA256 computation
 * @param data Data to compute SHA256 on
 * @param data_length Data length, max. 512 bytes
 * @param sha256 returned computed SHA256
 *
 * Compute SHA256 hash on the given data.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_sha256(const uint8_t* data, const uint16_t data_length,
		uint8_t* sha256);

/**
 * @brief Compute SHA256 on more than 512 bytes of data
 *
 * This function must be followed by calls to Secure Element_sha256_update() and
 * TO_sha256_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_sha256_init(void);

/**
 * @brief Update SHA256 computation with new data
 * @param data Data to compute SHA256 on
 * @param length Data length, max. 512 bytes
 *
 * This function can be called several times to provide data to compute SHA256
 * on, and must be called after TO_sha256_init().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED if not called after TO_sha256_init()
 * or TO_sha256_update()
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_sha256_update(const uint8_t* data, const uint16_t length);

/**
 * @brief Returns the SHA256 hash of the data previously given
 * @param sha256 returned computed SHA256
 *
 * This function must be called after TO_sha256_init() and
 * TO_sha256_update().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED if not called after TO_sha256_update()
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_sha256_final(uint8_t* sha256);

/** @} */

/** @addtogroup keys
 * @{ */

/**
 * @brief Set remote public key
 * @param key_index Index of the key to be set, starting from 0
 * @param public_key Key to set
 * @param signature Public key signature with the certificate previously sent
 * with verify_certificate_and_store()
 *
 * This command requests the Secure Element to store, at the given index, a
 * public key to be used in the ECIES process.
 *
 * A signature is attached to the new public key and must be verified with the
 * certificate previously sent using verify_certificate_and_store().
 * This command is disabled if public key is configured as non-writable during
 * (pre-)personalization.
 *
 * A CA signed certificate is first sent to the Secure Element using
 * verify_certificate_and_store(), get_challenge_and_store(), and
 * verify_challenge_signature() commands (remote authentication).  If the
 * Certificate Authority signature of the certificate is validated, the public
 * key of the certificate is stored. Then, this certificate is used to verify
 * the signature of any ephemeral public key sent using
 * set_remote_public_key().  The signature is calculated on all bytes of the
 * New Remote Public Key.  If the signature verification failed, Secure Element
 * will not store the public key.  Please refer to Secure Element Datasheet -
 * “Chain of Trust between Authentication and Secure Messaging” chapter for
 * more details.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_set_remote_public_key(const uint8_t key_index,
		const uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Renew ECC keys pair
 * @param key_index Index of the ECC key pair to renew, starting from 0
 *
 * Renews Elliptic Curve key pair for the corresponding index.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_renew_ecc_keys(const uint8_t key_index);

/**
 * @brief Get the public key corresponding to the given index, and the
 * signature of this public key.
 * @param key_index Public key index
 * @param public_key The requested public key
 * @param signature Public key signature, can be verified using the public key
 * of the certificate returned by GET_CERTIFICATE
 *
 * Signature can be verified using the public key of the certificate returned
 * by get_certificate().
 *
 * This signature is calculated on all bytes of the Public Key in the TO
 * response.
 * Key pair used to generate and verify this signature is the one associated to
 * certificate sent by the Secure Element in get_certificate() or
 * get_certificate_and_sign() commands.
 * Please refer to Secure Element Datasheet - “Chain of Trust between
 * Authentication and Secure Messaging” chapter for more details.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_INVALID_RESPONSE_LENGTH: invalid response length
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_get_public_key(const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Get the public key corresponding to the given index.
 * @param key_index Public key index
 * @param public_key The requested public key
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_INVALID_RESPONSE_LENGTH: invalid response length
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_get_unsigned_public_key(const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE]);

/**
 * @brief Renew shared keys
 * @param key_index Index of the Secure Element ephemeral public/private key
 * pair, starting from 0
 * @param public_key_index Index where the remote public key is stored in the
 * Secure Element, starting from 0.
 *
 * Renews shared keys (AES and HMAC), stored at the same index as Secure
 * Element ephemeral public/private key pair.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_renew_shared_keys(const uint8_t key_index,
		const uint8_t public_key_index);

/**
 * @brief Get key fingerprint
 * @param key_type Type of key
 * @param key_index Index of the key for given type starting from 0
 * @param fingerprint 3 bytes fingerprint of the key
 *
 * Retrieve the 3 bytes fingerprint of the key corresponding to given type and
 * index.
 *
 * See Secure Element Datasheet - "GET_KEY_FINGERPRINT" chapter for defails
 * about fingerprint computation.
 *
 * This function is available only for fixed keys.
 *
 * Note: all first keys of the same type have the same index. For example, the
 * first AES key and the first Public Key have both index 0.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key type and/or key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_key_fingerprint(TO_key_type_t key_type,
		uint8_t key_index,
		uint8_t* fingerprint[TO_KEY_FINGERPRINT_SIZE]);

/** @} */

/** @addtogroup encryption
 * @{ */

/**
 * @brief Encrypts data using AES128 algorithm in CBC mode of
 * operation.
 * @param key_index Index of the key to use for data encryption, starting
 * from 0
 * @param data Data to encrypt
 * @param data_length Length of the data to encrypt
 * @param initial_vector Initial vector
 * @param cryptogram Cryptogram
 *
 * As padding is not handled by the TO, you must ensure that data length is a
 * multiple of 16 and is not greater than maximum length value (512 bytes).
 * Initial vector is generated by the TO.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_INVALID_LEN: Wrong length
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_aes_encrypt(const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram);

/**
 * @brief Similar to encrypt() except that Initial Vector is
 * given by user
 * @param key_index Index of the key to use for data encryption, starting
 * from 0
 * @param initial_vector Random data (16 bytes)
 * @param data Data to encrypt
 * @param data_length
 * @param cryptogram Returned encrypted data
 *
 * It can be used to encrypt more than data size limit (512 bytes) by manually
 * chaining blocs of 512 bytes (see Secure Element Datasheet - "Encrypt or
 * decrypt more than 512 bytes" chapter for more details).
 * @warning Using IV_ENCRYPT with a predictable Initial Vector can have
 *    security impact. Please let Secure Element generates Initial Vector by
 *    using ENCRYPT command when possible.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_aes_iv_encrypt(const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram);

/**
 * @brief Reverse operation of encrypt().
 * @param key_index Index of the key to use for data decryption, starting
 * from 0
 * @param initial_vector Random data (16 bytes) generated by encrypt function
 * @param cryptogram Data to decrypt
 * @param cryptogram_length Cryptogram length, less or equal to 512 bytes
 * @param data returned decrypted data
 *
 * Requires the initial vector provided by the encryption function.
 *
 * Padding is not handled by Secure Element firmware. It gives the possibility
 * to avoid the case of a full padding block sometime required by padding
 * functions.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_aes_decrypt(const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data);

/** @} */

/** @addtogroup mac
 * @{ */

/**
 * @brief Computes a 256-bit HMAC tag based on SHA256 hash
 * function.
 * @param key_index Index of the key to use for HMAC calculation, starting
 * from 0
 * @param data Data to compute HMAC on
 * @param data_length
 * @param hmac_data Computed HMAC
 *
 * If you need to compute HMAC on more than 512 bytes, please use the sequence
 * compute_hmac_init(), compute_hmac_update(), ..., compute_hmac_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_compute_hmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t hmac_data[TO_HMAC_SIZE]);

/**
 * @brief Compute HMAC on more than 512 bytes of data
 * @param key_index Index of the key to use for HMAC calculation, starting
 * from 0
 *
 * This is the first command of the sequence compute_hmac_init(),
 * compute_hmac_update(), ..., compute_hmac_final().
 * It is used to Secure Element send Key_index.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_compute_hmac_init(uint8_t key_index);

/**
 * @brief Used to send data to compute HMAC on.
 * @param data Data to compute HMAC on
 * @param length Data length
 *
 * This command can be called several times, new data are added to the data
 * previously sent.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED: need to call compute_hmac_init() first
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_compute_hmac_update(const uint8_t* data, uint16_t length);

/**
 * @brief Returns computed HMAC
 * @param hmac Returned computed HMAC
 *
 * This is the last command of the sequence compute_hmac_init(),
 * compute_hmac_update(), ..., compute_hmac_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED: need to call compute_hmac_init() and
 * compute_hmac_update() first
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_compute_hmac_final(uint8_t hmac[TO_HMAC_SIZE]);

/**
 * @brief Verifies if the HMAC tag is correct for the given data
 * @param key_index Index of the key to use for HMAC calculation, starting
 * from 0
 * @param data Data to verify HMAC on
 * @param data_length
 * @param hmac_data returned computed HMAC
 *
 * If you need to verify HMAC of more than 512 bytes, please use the
 * combination of verify_hmac_init(), verify_hmac_update(), ...,
 * verify_hmac_final()
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_hmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t hmac_data[TO_HMAC_SIZE]);

/**
 * @brief Verify HMAC on more than 512 bytes of data
 * @param key_index Index of the key to use for HMAC calculation, starting
 * from 0
 *
 * When you need to verify HMAC of more than 512 bytes you need to call this
 * function first with the key index - as sent to verify_hmac().
 * Data will be sent with verify_hmac_update() and HMAC will be sent with
 * verify_hmac_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_hmac_init(uint8_t key_index);

/**
 * @brief Used to send data to verify HMAC on.
 * @param data Data to verify HMAC on
 * @param length Data length
 *
 * After calling verify_hmac_init() to provide key index, you can call
 * verify_hmac_update to send the data to verify HMAC on.
 * This command can be called several times, and new data are added to the
 * previous one for HMAC verification.
 * Last command to use is verify_hmac_final.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED: need to call VERIFY_HMAC_INIT first
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_hmac_update(const uint8_t* data, uint16_t length);

/**
 * @brief This command is used to send HMAC to verify
 * @param hmac HMAC to verify
 *
 * Data was previously sent by the sequence verify_hmac_init(),
 * verify_hmac_update(), ..., verify_hmac_final().
 * This command succeed if the HMAC is correct for the given data.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_COND_OF_USE_NOT_SATISFIED: verify_hmac_init() or verify_hmac_update
 *      were not called before this command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_hmac_final(const uint8_t hmac[TO_HMAC_SIZE]);

/**
 * @brief Compute CMAC
 * @param key_index Index of the key to use for CMAC calculation, starting
 * from 0
 * @param data Data to compute CMAC on
 * @param data_length
 * @param cmac_data Returned computed CMAC
 *
 * Compute a 128-bit CMAC tag based on AES128 algorithm.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_compute_cmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t cmac_data[TO_CMAC_SIZE]);

/**
 * @brief Verify CMAC
 * @param key_index Index of the key to use to compute the CMAC tag, starting
 * from 0
 * @param data Data to verify CMAC on
 * @param data_length
 * @param cmac_data expected CMAC
 *
 * Verify if the CMAC tag is correct for the given data.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_cmac(const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t cmac_data[TO_CMAC_SIZE]);

/** @} */

/** @addtogroup secmsg
 * @{ */

/**
 * @brief Transforms a message into a secured message
 * (cryptogram and HMAC tag).
 * @param aes_key_index Index of the key to use for data encryption, starting
 * from 0
 * @param hmac_key_index Index of the key to use for HMAC, starting from 0
 * @param data Message to be secured
 * @param data_length
 * @param initial_vector Block of 16 random bytes generated by the Secure
 * Element and required to decrypt the data
 * @param cryptogram Message cryptogram (same size as data)
 * @param hmac Message HMAC
 *
 * It is equivalent to call encrypt() command, then compute_hmac() on the
 * result.
 * The HMAC tag is calculated on encrypted data.
 * Typical use is to have the same value to both AES and HMAC Key indexes.
 * If remote public key is known and trusted by TO, the TO’s public key could
 * be added to the result of this command and could be used on to have one way
 * only communication network (from Secure Element to remote only).
 *
 * Note: As padding is not handled by the TO, you must ensure that data length
 * is a multiple of 16 and is not greater than maximum length value (512
 * bytes).
 * Initial vector is generated by the Secure Element and not included in the
 * data length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_secure_message(const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint8_t hmac[TO_HMAC_SIZE]);

/**
 * @brief Reverse operation of secure_message()
 * @param aes_key_index Index of the key to use for data decryption, starting
 * from 0
 * @param hmac_key_index Index of the key to use for HMAC verification,
 * starting from 0
 * @param initial_vector Initial vector for decryption
 * @param cryptogram Message cryptogram
 * @param cryptogram_length
 * @param hmac Expected HMAC
 * @param data Decrypted data
 *
 * Data are decrypted only if the HMAC tag is valid.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_unsecure_message(const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t hmac[TO_HMAC_SIZE],
		uint8_t* data);

/** @} */

/** @addtogroup auth
 * @{ */

/**
 * @brief Returns the Elliptic Curve Digital Signature of the given data
 * @param key_index Key index to use for signature
 * @param challenge Challenge to be signed
 * @param challenge_length
 * @param signature Returned challenge signature
 *
 * Signature Size is twice the size of the ECC key in bytes.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_sign(const uint8_t key_index, uint8_t* challenge,
		const uint16_t challenge_length, uint8_t* signature);

/**
 * @brief Verifies the given Elliptic Curve Digital Signature of the
 * given data
 * @param key_index Key index to use for verification
 * @param data Data to verify signature on
 * @param data_length
 * @param signature Expected data signature
 *
 * The public key used for the signature verification must be previously
 * provided using the SET_REMOTE_PUBLIC_KEY command.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify(const uint8_t key_index, uint8_t* data,
		const uint16_t data_length, const uint8_t* signature);

/**
 * @brief Returns the Elliptic Curve Digital Signature of the given
 * hash
 * @param key_index Key index to use for signature
 * @param hash Hash to be signed
 * @param signature Returned hash signature
 *
 * Signature Size is twice the size of the ECC key in bytes.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_sign_hash(const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], uint8_t* signature);

/**
 * @brief Verifies the given Elliptic Curve Digital
 * Signature of the given hash
 * @param key_index Key index to use for verification
 * @param hash Hash to verify signature on
 * @param signature Expected hash signature
 *
 * The public key used for the signature verification must be previously
 * provided using the SET_REMOTE_PUBLIC_KEY command.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_hash_signature(const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], const uint8_t* signature);

/**
 * @brief Returns subject common name of one of the Secure Element certificates
 * @param certificate_index Requested certificate index
 * @param subject_cn Returned certificate subject common name null terminated
 * string
 *
 * Request a certificate subject common name to Secure Element according to the
 * given index.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_certificate_subject_cn(const uint8_t certificate_index,
		char subject_cn[TO_CERT_SUBJECT_CN_MAXSIZE + 1]);

/**
 * @brief Returns one of the Secure Element certificates
 * @param certificate_index Requested certificate index
 * @param format Requested certificate format
 * @param certificate Certificate, size depends on the certificate type (see
 * TO_cert_*_t)
 *
 * Request a certificate to Secure Element according to the given index and
 * format.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_certificate(const uint8_t certificate_index,
		const TO_certificate_format_t format, uint8_t* certificate);

/**
 * @brief Returns one of the Secure Element certificates, x509 DER formated
 * @param certificate_index Requested certificate index
 * @param certificate Returned certificate data, this buffer must be at least
 * TO_MAXSIZE
 * @param size Returned certificate real size (which is less or equal to 512
 * bytes)
 *
 * Request a x509 DER formated certificate to Secure Element according to the
 * given index.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_certificate_x509(const uint8_t certificate_index,
		uint8_t* certificate, uint16_t* size);

/**
 * @brief Returns one of the Secure Element certificates, and a challenge
 * signed with the certificate private key
 * @param certificate_index Index of the certificate to return, starting from 0
 * @param format Format of the TO’s certificate, read the Secure Element
 * Datasheet, "Certificates description" chapter
 * @param challenge Challenge to be signed
 * @param challenge_length Length of the challenge to be signed
 * @param certificate Certificate, size depends on the certificate type (see
 * TO_cert_*_t)
 * @param signature Returned signature
 *
 * This command is equivalent to GET_CERTIFICATE and SIGN commands in only 1
 * message.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INVALID_LEN: wrong length
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_get_certificate_and_sign(const uint8_t certificate_index,
		const TO_certificate_format_t format,
		uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint8_t* signature);

/**
 * @brief Returns one of the Secure Element x509 DER formated certificates, and
 * a challenge signed with the certificate private key
 * @param certificate_index Index of the certificate to return, starting from 0
 * @param challenge Challenge to be signed
 * @param challenge_length Length of the challenge to be signed
 * @param certificate Returned certificate data, this buffer must be at least
 * TO_MAXSIZE
 * @param size Returned certificate real size (which is less or equal to 512
 * bytes)
 * @param signature Returned signature
 *
 * This command is equivalent to GET_CERTIFICATE and SIGN commands in only 1
 * message.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INVALID_LEN: wrong length
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid Certificate Number
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_get_certificate_x509_and_sign(const uint8_t certificate_index,
		uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint16_t* size, uint8_t* signature);

/**
 * @brief Requests to verify Certificate
 * Authority Signature of the given certificate, if verification succeeds, this
 * certificate is stored into Secure Element Memory.
 * @param ca_key_id Index of the Certificate Authority public Key
 * @param format Format of the certificate
 * @param certificate Certificate to be verified and stored
 *
 * This command is required before using GET_CHALLENGE_AND_STORE and
 * VERIFY_CHALLENGE_SIGNATURE.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: certificate Format not supported
 * - TORSP_ARG_OUT_OF_RANGE: invalid CA Key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_certificate_and_store(const uint8_t ca_key_id,
		const TO_certificate_format_t format, uint8_t* certificate);

/**
 * @brief Requests to verify CA Certificate
 * Authority Signature of the given certificate, if verification succeeds, this
 * certificate is stored into Secure Element Memory.
 * @param ca_key_index CA index to verify subCA
 * @param subca_key_index subCA index to store subCA
 * @param certificate Certificate to be verified and stored
 * @param certificate_len Certificate length
 *
 * Note: the only supported certificate format for this command is DER X509.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid CA Key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_ca_certificate_and_store(const uint8_t ca_key_index,
		const uint8_t subca_key_index, const uint8_t *certificate,
		const uint16_t certificate_len);

/**
 * @brief Returns a challenge (random number of fixed
 * length) and store it into Secure Element memory.
 * @param challenge Returned challenge
 *
 * This command must be called before VERIFY_CHALLENGE_SIGNATURE.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_challenge_and_store(
		uint8_t challenge[TO_CHALLENGE_SIZE]);

/**
 * @brief Verifies if the given signature matches
 * with the signature of the challenge previously sent by
 * GET_CHALLENGE_AND_STORE, using the public key of the certificate previously
 * sent by VERIFY_CERTIFICATE_AND_STORE.
 * @param signature Challenge signature to verify
 *
 * Note: VERIFY_CERTIFICATE_AND_STORE must be called before this command.
 * GET_CHALLENGE_AND_STORE must be called before this command.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_COND_OF_USE_NOT_SATISFIED: VERIFY_CERTIFICATE_AND_STORE and
 *      GET_CHALLENGE_AND_STORE were not called before this command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_challenge_signature(
		const uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Initialize certificate chain verification
 * @param ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 *
 * This command is required before using
 * VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_chain_certificate_and_store_init(
		const uint8_t ca_key_index);

/**
 * @brief Update certificate chain verification with certificate chain data.
 *
 * This command must be used after
 * VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE_INIT and is required before using
 * VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE_FINAL and can be repeated to deal
 * with certificate chains longer than 512 bytes.
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Final certificate
 * - Intermediate CA certificates (if any)
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Certificate chain can be cut anywhere.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_chain_certificate_and_store_update(
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

/**
 * @brief Finalize certificate chain verification.
 *
 * This command must be used after
 * VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE_UPDATE to verify last certificate
 * and store final certificate.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_chain_certificate_and_store_final(void);

/**
 * @brief Initialize CA certificate chain verification
 * @param ca_key_index CA key index (use TO_CA_IDX_AUTO to enable Authority Key
 *                     Identifier based CA detection)
 * @param subca_key_index subCA index to store subCA
 *
 * This command is required before using
 * VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_chain_ca_certificate_and_store_init(
		const uint8_t ca_key_index, const uint8_t subca_key_index);

/**
 * @brief Update CA certificate chain verification with certificate chain data.
 *
 * This command must be used after
 * VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE_INIT and is required before
 * using VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE_FINAL and can be repeated
 * to deal with certificate chains longer than 512 bytes.
 *
 * Certificates must be in X509 DER (binary) format.
 * Certificates must be ordered as following:
 * - Intermediate CA certificates
 * - Root CA certificate (optional as it must already be trusted by the
 *   Secure Element)
 *
 * Certificate chain can be cut anywhere.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_chain_ca_certificate_and_store_update(
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

/**
 * @brief Finalize certificate chain verification.
 *
 * This command must be used after
 * VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE_UPDATE to verify last
 * certificate and store first intermediate CA certificate.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid signature
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_verify_chain_ca_certificate_and_store_final(void);

/** @} */

/** @addtogroup nvm
 * @{ */

/**
 * @brief Write data to Secure Element NVM reserved zone.
 * @param offset Offset in zone to write data
 * @param data Buffer containing data to send
 * @param length Amount of data to send in bytes (512 bytes max.)
 * @param key Key used to read/write previous data
 *
 * @return TO_OK if data has been written sucessfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_ERROR if an internal error has occured
 */
TO_API int TO_write_nvm(const uint16_t offset, const void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE]);

/**
 * @brief Read data from Secure Element NVM reserved zone.
 * @param offset Offset in zone to read data
 * @param data Buffer to store data
 * @param length Amount of data to read in bytes (512 bytes max.)
 * @param key Key used to write data
 *
 * @return TO_OK if data has been written sucessfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_ERROR if an internal error has occured
 */
TO_API int TO_read_nvm(const uint16_t offset, void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE]);

/**
 * @brief Get NVM reserved zone available size.
 * @param size NVM size
 *
 * @return TO_OK if size has been retrieved sucessfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_ERROR if an internal error has occured
 */
TO_API int TO_get_nvm_size(uint16_t *size);

/** @} */

/** @addtogroup tls
 * @{ */

/**
 * @brief Set TLS server random
 * @param random Server random including a timestamp as prefix
 *
 * Send TLS server random to Secure Element.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_set_tls_server_random(
		uint8_t random[TO_TLS_RANDOM_SIZE]);

/**
 * @brief Set TLS server ephemeral public key
 * @param key_index Index of the public key to update
 * @param ecc_params Includes curve type, format and name, length of the public
 * key concatenated with the uncompression tag (0x04)
 * @param signature Signature of the concatenation of 'client_random',
 * 'server_random' and 'ecc_params'
 *
 * Send TLS server ephemeral public key to Secure Element.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_set_tls_server_eph_pub_key(
		uint8_t key_index,
		uint8_t ecc_params[TO_TLS_SERVER_PARAMS_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Get TLS random
 * @param timestamp POSIX timestamp (seconds since January 1st 1970 00:00:00
 * UTC)
 * @param random Returned random challenge
 *
 * Get TLS random from Secure Element.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_get_tls_random_and_store(
		uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t random[TO_TLS_RANDOM_SIZE]);

/**
 * @brief Get TLS master secret.
 * @param master_secret returned master secret
 *
 * Request TLS master secret to Secure Element.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid certificate index
 * - TO_INVALID_RESPONSE_LENGTH: invalid response length
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_get_tls_master_secret(
		uint8_t master_secret[TO_TLS_MASTER_SECRET_SIZE]);

/**
 * @brief Renew TLS keys
 * @param key_index Index of TLS keys to renew
 * @param enc_key_index Index to store encryption AES/HMAC keys
 * @param dec_key_index Index to store decryption AES/HMAC keys
 *
 * Renew TLS keys with a master secret derivation.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid certificate index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_renew_tls_keys(const uint8_t key_index,
		const uint8_t enc_key_index, const uint8_t dec_key_index);

/**
 * @brief Derive master secret.
 * @param kpriv_index Index of the private key to use
 * @param kpub_index Index of the remote public key to use
 * @param enc_key_index Index to store encryption AES/HMAC keys
 * @param dec_key_index Index to store decryption AES/HMAC keys
 *
 * ECDHE method.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid certificate index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_renew_tls_keys_ecdhe(const uint8_t kpriv_index,
		const uint8_t kpub_index, const uint8_t enc_key_index,
		const uint8_t dec_key_index);

/**
 * @brief Calculate finished
 * @param from 0 if message is from client, 1 if it is from server
 * @param handshake_hash Hash of all handshake messages
 * @param finished Result
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element136
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element136
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_calculate_finished(const int from,
		const uint8_t handshake_hash[TO_HASH_SIZE],
		uint8_t finished[TO_TLS_FINISHED_SIZE]);

/** @} */

/** @addtogroup tlsoptim
 * @{ */

/**
 * @brief Reset TLS session.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_reset(void);

/**
 * @brief Set TLS mode (version and TLS/DTLS) (resets TLS handshake in case of
 * change).
 * @param mode TLS mode
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_set_mode(const TO_tls_mode_t mode);

/**
 * @brief Get TLS ClientHello
 * @param timestamp Timestamp (seconds since epoch)
 * @param client_hello ClientHello payload
 * @param client_hello_len ClientHello payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_client_hello(const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t *client_hello, uint16_t *client_hello_len);

/**
 * @brief Handle TLS HelloVerifyRequest
 * @param hello_verify_request HelloVerifyRequest payload
 * @param hello_verify_request_len HelloVerifyRequest payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_hello_verify_request(
		const uint8_t *hello_verify_request,
		const uint32_t hello_verify_request_len);

/**
 * @brief Handle TLS ServerHello
 * @param server_hello ServertHello payload
 * @param server_hello_len ServertHello payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_server_hello(const uint8_t *server_hello,
		const uint32_t server_hello_len);

/**
 * @brief Handle TLS Server Certificate header
 * @param server_certificate_init Certificate payload header
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_server_certificate_init(
		const uint8_t server_certificate_init[TO_TLS_SERVER_CERTIFICATE_INIT_SIZE]);

/**
 * @brief Handle TLS Server Certificate partial payload
 * @param server_certificate_update Certificate partial payload
 * @param server_certificate_update_len Certificate partial payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_server_certificate_update(
		const uint8_t *server_certificate_update,
		const uint32_t server_certificate_update_len);

/**
 * @brief Finish TLS Server Certificate handling
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_server_certificate_final(void);

/**
 * @brief Handle TLS ServerKeyExchange
 * @param server_key_exchange ServerKeyExchange payload
 * @param server_key_exchange_len ServerKeyExchange payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_server_key_exchange(const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len);

/**
 * @brief Handle TLS CertificateRequest
 * @param certificate_request CertificateRequest payload
 * @param certificate_request_len CertificateRequest payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_certificate_request(const uint8_t *certificate_request,
		const uint32_t certificate_request_len);

/**
 * @brief Handle TLS ServerHelloDone
 * @param server_hello_done ServerHelloDone payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_server_hello_done(
		const uint8_t server_hello_done[TO_TLS_SERVER_HELLO_DONE_SIZE]);

/**
 * @brief Get TLS Certificate
 * @param certificate Certificate payload
 * @param certificate_len Certificate payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_certificate(
		uint8_t *certificate, uint16_t *certificate_len);

/**
 * @brief Get TLS Certificate initialization
 * @param certificate Certificate payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_certificate_init(
		uint8_t certificate[TO_TLS_CLIENT_CERTIFICATE_INIT_SIZE]);

/**
 * @brief Get TLS Certificate update
 * @param certificate Certificate payload
 * @param certificate_len Certificate payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_certificate_update(
		uint8_t *certificate, uint16_t *certificate_len);

/**
 * @brief Get TLS Certificate finalize
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_certificate_final(void);

/**
 * @brief Get TLS ClientKeyExchange
 * @param client_key_exchange ClientKeyExchange payload
 * @param client_key_exchange_len ClientKeyExchange payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_client_key_exchange(
		uint8_t *client_key_exchange,
		uint16_t *client_key_exchange_len);

/**
 * @brief Get TLS CertificateVerify
 * @param certificate_verify CertificateVerify payload
 * @param certificate_verify_len CertificateVerify payload length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_certificate_verify(
		uint8_t certificate_verify[TO_TLS_CERTIFICATE_VERIFY_MAXSIZE],
		uint16_t *certificate_verify_len);

/**
 * @brief Get TLS ChangeCipherSpec
 * @param change_cipher_spec ChangeCipherSpec payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_change_cipher_spec(
		uint8_t change_cipher_spec[TO_TLS_CHANGE_CIPHER_SPEC_SIZE]);

/**
 * @brief Get TLS Finished
 * @param finished Finish payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_get_finished(
		uint8_t finished[TO_TLS_FINISHED_PAYLOAD_SIZE]);

/**
 * @brief Handle TLS ChangeCipherSpec
 * @param change_cipher_spec ChangeCipherSpec payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_change_cipher_spec(
		const uint8_t change_cipher_spec[TO_TLS_CHANGE_CIPHER_SPEC_SIZE]);

/**
 * @brief Handle TLS Finished
 * @param finished Finished payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_handle_finished(
		const uint8_t finished[TO_TLS_FINISHED_PAYLOAD_SIZE]);

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
TO_API int TO_tls_secure_message(const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t* data, const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram, uint16_t *cryptogram_len);

/**
 * @brief Secure message with TLS initialization
 * @param header TLS header
 * @param initial_vector Initial vector used to encrypt
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_secure_message_init(const uint8_t header[TO_TLS_HEADER_SIZE],
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE]);

/**
 * @brief Update secure message data to secure message with TLS
 * @param data TLS data
 * @param data_len TLS data length (must be 16 bytes aligned, last unaligned
 * bytes must be sent with `TO_tls_secure_message_final`
 * @param cryptogram Securized data
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_secure_message_update(const uint8_t* data,
		const uint16_t data_len, uint8_t *cryptogram);

/**
 * @brief Secure message with TLS finalization
 * @param data TLS end data
 * @param data_len TLS end data length (must be less than 16 bytes)
 * @param cryptogram Securized message last blocks
 * @param cryptogram_len Securized message last blocks length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_secure_message_final(const uint8_t* data, const uint16_t data_len,
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
TO_API int TO_tls_unsecure_message(const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len);

/**
 * @brief Unsecure message with TLS initialization
 * @param cryptogram_len Cryptogram length
 * @param header TLS header
 * @param initial_vector Initial vector used to encrypt
 * @param last_block_iv Last AES block initial vector (penultimate block)
 * @param last_block Last AES block
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_unsecure_message_init(const uint16_t cryptogram_len,
		const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);

/**
 * @brief Update unsecure message data to unsecure message with TLS
 * @param cryptogram Securized message (without header and initial vector)
 * @param cryptogram_len Securized message (without header and initial vector)
 * length
 * @param data TLS clear data
 * @param data_len TLS clear data length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_unsecure_message_update(const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len);

/**
 * @brief Unsecure message with TLS finalization
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid HMAC
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TO_API int TO_tls_unsecure_message_final(void);

/** @} */

/** @addtogroup lora
 * @{ */

/**
 * @brief Computes the LoRaMAC frame MIC field
 * @param data Data buffer
 * @param data_length Data buffer size
 * @param address Frame address
 * @param direction: Frame direction [0: uplink, 1 downlink]
 * @param seq_counter Frame sequence counter
 * @param mic Computed MIC field
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_compute_mic(const uint8_t *data, uint16_t data_length,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t mic[TO_LORA_MIC_SIZE]);

/**
 * @brief Computes the LoRaMAC payload encryption
 * @param data Data buffer
 * @param data_length Data buffer size
 * @param fport Frame port (as pointer to keep retrocompatibility)
 * @param address Frame address
 * @param direction: Frame direction [0: uplink, 1 downlink]
 * @param seq_counter Frame sequence counter
 * @param enc_buffer Encrypted buffer
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_encrypt_payload(const uint8_t *data,
		uint16_t data_length, const uint8_t *fport,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t *enc_buffer);

/**
 * @brief Computes the LoRaMAC Join Request frame
 * MIC field
 * @param data Data buffer
 * @param data_length Data buffer size
 * @param mic Computed MIC field
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_join_compute_mic(const uint8_t *data,
		uint16_t data_length, uint8_t mic[TO_LORA_MIC_SIZE]);

/**
 * @brief Computes the LoRaMAC join frame decryption
 * MIC field
 * @param data Data buffer
 * @param data_length Data buffer size
 * @param dec_buffer Decrypted buffer
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_decrypt_join(const uint8_t *data, uint16_t data_length,
		uint8_t *dec_buffer);

/**
 * @brief Computes the LoRaMAC join frame decryption
 * @param app_nonce Application nonce
 * @param net_id Network ID
 * @param dev_nonce Device nonce
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_compute_shared_keys(const uint8_t *app_nonce,
		const uint8_t *net_id, uint16_t dev_nonce);

/**
 * @brief Get AppEUI
 * @param app_eui Application EUI
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_get_app_eui(uint8_t app_eui[TO_LORA_APPEUI_SIZE]);

/**
 * @brief Get DevEUI
 * @param dev_eui Device EUI
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_get_dev_eui(uint8_t dev_eui[TO_LORA_DEVEUI_SIZE]);

/** @} */

/** @addtogroup loraoptim
 * @{ */

/**
 * @brief Get encrypted join request payload
 * @param data Join request payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_get_join_request_phypayload(
		uint8_t data[TO_LORA_JOINREQUEST_SIZE]);

/**
 * @brief Handle encrypted join accept
 * payload
 * @param data Join accept payload (MHDR + payload + MIC)
 * @param data_length Join accept payload size
 * @param dec_buffer Decrypted join accept payload
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_handle_join_accept_phypayload(const uint8_t *data,
		const uint16_t data_length, uint8_t *dec_buffer);

/**
 * @brief Encrypt PHYPayload
 * @param mhdr MHDR
 * @param fctrl Frame control
 * @param fopts Frame options (optional, FCtrl FOptsLen part must be 0 if
 * missing)
 * @param fport  Frame port (optional, must be present if payload_size > 0)
 * @param payload  payload to encrypt (optional)
 * @param payload_size  payload size (must be 0 if payload is null)
 * @param enc_buffer: Encrypted PHYPayload (size TO_LORA_MHDR_SIZE +
 *              TO_LORA_DEVADDR_SIZE + TO_LORA_FCTRL_SIZE +
 *              TO_LORA_FCNT_SIZE / 2 + FOptLen + (payload_size ?
 *              payload_size + 1 : 0) + TO_LORA_MIC_SIZE)
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_secure_phypayload(const uint8_t mhdr,
		const uint8_t fctrl, const uint8_t *fopts, const uint8_t fport,
		const uint8_t *payload, const int payload_size,
		uint8_t *enc_buffer);

/**
 * @brief Decrypt PHYPayload
 * @param data PHYPayload to decrypt
 * @param data_length PHYPayload size
 * @param dec_buffer: Decrypted PHYPayload (size data_length -
 * TO_LORA_MIC_SIZE)
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occured while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TO_API int TO_lora_unsecure_phypayload(const uint8_t *data,
		const uint16_t data_length, uint8_t *dec_buffer);

/** @} */

/** @addtogroup seclink
 * @{ */

/**
 * @brief Reset secure link.
 *
 * This function can be used to initialize secure link, after each
 * successful TO_init() calls.
 * If not called manually after TO_init(), it is automatically called on
 * first command.
 *
 * According to secure link protocol, this function may reset some internal
 * state, request an initial vector from Secure Element, etc...
 *
 * @return TO_OK on reset success, secure link is ready to be used.
 */
TO_API int TO_seclink_reset(void);

/**
 * @brief Secure link callback prototype to store keys.
 * @param data New keys to save, data format depends on the used secure link
 * protocol.
 *
 * Callback prototype for an user function to be called in case of secure link
 * keys renewal.
 * This function is expected to store the new keys persistently, in replacement
 * of the old ones.
 * The storage method depends on the user environment, and is to be implemented
 * according to it.
 *
 * @warning Do not do libTO functions calls from this callback.
 *
 * See TO_seclink_set_store_keys_cb().
 *
 * @return TO_OK on success
 */
typedef int (*TO_seclink_store_keys_cb)(void *data);

/**
 * @brief Secure link callback to load keys.
 * @param data Pre-allocated to return loaded keys, data format depends on the
 * used secure link protocol.
 *
 * Callback prototype for an user function to be called by the library when it
 * needs keys to use secure link.
 * It may be called by the library on every Secure Element function call.
 * This function is expected to read the keys from an user persistent storage.
 *
 * @warning Do not do libTO functions calls from this callback.
 *
 * See TO_seclink_set_load_keys_cb().
 *
 * @return TO_OK on success
 */
typedef int (*TO_seclink_load_keys_cb)(void *data);

/**
 * @brief Set secure link keys storage callback.
 * @param cb Callback function pointer, see TO_seclink_store_keys_cb.
 *
 * This function is used to set secure link keys storage callback. The callback
 * function will be used by the library to allow user to store new keys in
 * remplacement of the old ones in cases of a secure link keys renewal
 * procedure.
 *
 * This function has to be called just after TO_init() if secure link is used
 * by the project with a keys renewal mechanism enabled.
 * In this case, do not use Secure Element APIs before having defined and set
 * this callback, or you may miss keys storage notifications if a keys renewal
 * procedure occurs.
 */
TO_API void TO_seclink_set_store_keys_cb(TO_seclink_store_keys_cb cb);

/**
 * @brief Set secure link callback to load keys.
 * @param cb Callback function pointer, see TO_seclink_load_keys_cb.
 *
 * This function is used to set secure link callback used by the library to
 * load keys.
 * The callback function will be called later by the library.
 *
 * This function has to be called just after TO_init().
 */
TO_API void TO_seclink_set_load_keys_cb(TO_seclink_load_keys_cb cb);

/**
 * @brief Get secure link renewed keys.
 *
 * This function can only be used if you have the old keys.
 * When using this function, it calls the configured secure link key renewal
 * callback, allowing user to store the new key.
 *
 * See TO_seclink_set_key_renewal_cb() and TO_seclink_keys_renewal_cb.
 */
TO_API int TO_seclink_request_renewed_keys(void);

/**
 * @brief Bypass Secure Element secure link and use clear text
 * ones.
 * @param bypass Set to 1 to bypass secure link, set to 0 to use secure
 * commands.
 *
 * If called just after TO_init(), TO_seclink_reset() will not be called
 * automatically.
 * According to Secure Element settings, bypassing secure link may be
 * impossible.
 *
 * @return Previous secure link bypassing state.
 */
TO_API int TO_seclink_bypass(int bypass);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
