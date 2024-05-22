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
 * @file TO_cfg.h
 * @brief This file provides a way to configure libTO build.
 *
 * Please read the library configuration documentation chapter before modifying
 * this file.
 */

#ifndef _TO_CFG_H_
#define _TO_CFG_H_

/*
 * ---------------
 * Global settings
 * ---------------
 */

/*
 * Enable library debug mode
 * Prints out logs messages about the library behavior and internal steps.
 */
//#define TO_DEBUG 1

/*
 * Endianness settings
 * By default runtime detection is performed if none of the options below is
 * enabled.
 */
/* Force big endian */
//#define TO_BIG_ENDIAN 1
/* (or) Force little endian */
//#define TO_LITTLE_ENDIAN 1
/* (or) If your build environment provides endian.h */
//#define HAVE_ENDIAN_H 1

/*
 * Enable ability to configure I2C wrapper
 */
//#define TO_I2C_WRAPPER_CONFIG 1

/*
 * ------------------------
 * Features macro. settings
 * ------------------------
 */

/*
 * LoRa
 */
//#define TO_DISABLE_LORA 1

/*
 * LoRa optimized
 */
//#define TO_DISABLE_LORA_OPTIMIZED 1

/*
 * TLS
 */
//#define TO_DISABLE_TLS 1

/*
 * TLS handshake helper
 */
//#define TO_DISABLE_TLS_HELPER 1

/*
 * TLS optimized
 */
//#define TO_DISABLE_TLS_OPTIMIZED 1

/*
 * DTLS
 */
//#define TO_ENABLE_DTLS 1

/*
 * DTLS retransmission
 */
//#define TO_DISABLE_DTLS_RETRANSMISSION 1

/*
 * ECIES sequence helper
 */
//#define TO_DISABLE_ECIES_HELPER 1

/*
 * Secure Element informations
 * (get_sn, get_pn, ...)
 */
//#define TO_DISABLE_TO_INFO 1

/*
 * Random number generator
 */
//#define TO_DISABLE_API_GET_RANDOM 1

/*
 * Certificate management
 */
//#define TO_DISABLE_CERT_MGMT 1

/*
 * Signing and verification
 */
//#define TO_DISABLE_SIGNING 1

/*
 * AES encryption/decryption
 */
//#define TO_DISABLE_AES_ENCRYPT 1

/*
 * Secure messaging
 */
//#define TO_DISABLE_SEC_MSG 1

/*
 * SHA256 hash
 */
//#define TO_DISABLE_SHA256 1

/*
 * Keys management
 */
//#define TO_DISABLE_KEYS_MGMT 1

/*
 * HMAC computation/verification
 */
//#define TO_DISABLE_HMAC 1

/*
 * CMAC computation/verification
 */
//#define TO_DISABLE_CMAC 1

/*
 * NVM secure storage
 */
//#define TO_DISABLE_NVM 1

/*
 * Secure Element status PIO settings
 */
//#define TO_DISABLE_STATUS_PIO_CONFIG 1

/*
 * ------------------------
 * Features micro. settings
 * ------------------------
 */

/*
 * To disable (do not build) a specific API
 * Replace <API_NAME> by the uppercase API name.
 */
//#define TO_DISABLE_API_<API_NAME>

/*
 * --------------
 * Expert options
 * --------------
 */

/*
 * /!\ EXPERT
 * Customize internal I/O buffer size
 */
//#define TO_LIB_INTERNAL_IO_BUFFER_SIZE 640

/*
 * /!\ EXPERT
 * Customize maximum number of parameters taken by commands, for internal
 * library use
 */
//#define TO_CMD_MAX_PARAMS 10

/*
 * /!\ EXPERT
 * Customize internal TLS I/O buffer size
 */
//#define TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE 1024

/*
 * /!\ EXPERT
 * Customize internal TLS flight buffer size
 */
//#define TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE 2048

#endif
