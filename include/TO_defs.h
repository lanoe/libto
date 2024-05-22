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
 * @file TO_defs.h
 * @brief Secure Element constants.
 */

#ifndef _TO_DEFS_H_
#define _TO_DEFS_H_

#include <TO_stdint.h>
#include <TO_cfg.h>

/** @addtogroup errcodes
 * Error codes
 * @{ */

/*
 * Library error codes.
 * Note: the LSB is left empty because it is reserved for Secure Element device
 * error codes, then it is possible to return Secure Element and library error
 * codes in one single variable.
 */
#define TO_OK 0x0000
#define TO_MEMORY_ERROR 0x0100
#define TO_DEVICE_WRITE_ERROR 0x0200
#define TO_DEVICE_READ_ERROR 0x0400
#define TO_INVALID_CA_ID 0x1000
#define TO_INVALID_CERTIFICATE_FORMAT 0x1100
#define TO_INVALID_CERTIFICATE_NUMBER 0x1200
#define TO_INVALID_RESPONSE_LENGTH 0x2000
#define TO_SECLINK_ERROR 0x2100
#define TO_TIMEOUT 0x2200
#define TO_AGAIN 0x2400
#define TO_NOT_IMPLEMENTED 0x8000
#define TO_ERROR 0xF000

/** @} */

/** @addtogroup seerrcodes
 * Secure Element response codes
 * @{ */

#define TORSP_SUCCESS ((unsigned char)0x90)
#define TORSP_UNKNOWN_CMD ((unsigned char)0x01)
#define TORSP_BAD_SIGNATURE ((unsigned char)0x66)
#define TORSP_INVALID_LEN ((unsigned char)0x67)
#define TORSP_NOT_AVAILABLE ((unsigned char)0x68)
#define TORSP_INVALID_PADDING ((unsigned char)0x69)
#define TO136RSP_COM_ERROR ((unsigned char)0x72)
/* Authentication status does not allow the requested command */
#define TORSP_NEED_AUTHENTICATION ((unsigned char)0x80)
/* Security condition not satisfied */
#define TORSP_COND_OF_USE_NOT_SATISFIED ((unsigned char)0x85)
#define TORSP_ARG_OUT_OF_RANGE ((unsigned char)0x88)
#define TORSP_SECLINK_RENEW_KEY ((unsigned char)0xFD)
#define TORSP_INTERNAL_ERROR ((unsigned char)0xFE)

/** @} */

/** @addtogroup keytypes
 * @{ */

/**
 * Secure Element key types
 */
enum TO_key_type_e {
	KTYPE_CERT_KPUB = 0x00,
	KTYPE_CERT_KPRIV = 0x01,
	KTYPE_CA_KPUB = 0x02,
	KTYPE_REMOTE_KPUB = 0x03,
	KTYPE_ECIES_KPUB = 0x04,
	KTYPE_ECIES_KPRIV = 0x05,
	KTYPE_ECIES_KAES = 0x06,
	KTYPE_ECIES_KMAC = 0x07,
	KTYPE_LORA_KAPP = 0x08,
	KTYPE_LORA_KNET = 0x09,
	KTYPE_LORA_KSAPP = 0x0A,
	KTYPE_LORA_KSNET = 0x0B
};
typedef enum TO_key_type_e TO_key_type_t;

/** @} */

/** @addtogroup cmdcodes Secure Element command codes
 * Secure Element command codes
 * @{ */

/* System */
#define TOCMD_GET_SN ((unsigned short)0x0001)
#define TOCMD_RES ((unsigned short)0x0000)
#define TOCMD_GET_PN ((unsigned short)0x0002)
#define TOCMD_GET_HW_VERSION ((unsigned short)0x0003)
#define TOCMD_GET_SW_VERSION ((unsigned short)0x0004)
#define TOCMD_GET_RANDOM ((unsigned short)0x0005)
#define TOCMD_ECHO ((unsigned short)0x0010)
#define TOCMD_SLEEP ((unsigned short)0x0011)
#define TOCMD_READ_NVM ((unsigned short)0x0021)
#define TOCMD_WRITE_NVM ((unsigned short)0x0022)
#define TOCMD_GET_NVM_SIZE ((unsigned short)0x0050)
#define TOCMD_SET_STATUS_PIO_CONFIG ((unsigned short)0x00B1)
#define TOCMD_GET_STATUS_PIO_CONFIG ((unsigned short)0x00B2)

/* Secure Element Authentication */
#define TOCMD_GET_CERTIFICATE_SUBJECT_CN ((unsigned short)0x0046)
#define TOCMD_GET_CERTIFICATE ((unsigned short)0x0006)
#define TOCMD_SIGN ((unsigned short)0x0007)
#define TOCMD_VERIFY ((unsigned short)0x0012)
#define TOCMD_SIGN_HASH ((unsigned short)0x001E)
#define TOCMD_VERIFY_HASH_SIGNATURE ((unsigned short)0x001F)
#define TOCMD_GET_CERTIFICATE_AND_SIGN ((unsigned short)0x0008)

/* Remote device Authentication */
#define TOCMD_VERIFY_CERTIFICATE_AND_STORE ((unsigned short)0x0009)
#define TOCMD_VERIFY_CA_CERTIFICATE_AND_STORE ((unsigned short)0x0047)
#define TOCMD_GET_CHALLENGE_AND_STORE ((unsigned short)0x000A)
#define TOCMD_VERIFY_CHALLENGE_SIGNATURE ((unsigned short)0x000B)
#define TOCMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_INIT ((unsigned short)0x00AD)
#define TOCMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE ((unsigned short)0x00AE)
#define TOCMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_FINAL ((unsigned short)0x00AF)
#define TOCMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_INIT ((unsigned short)0x00B3)
#define TOCMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE ((unsigned short)0x00B4)
#define TOCMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_FINAL ((unsigned short)0x00B5)

/* HMAC */
#define TOCMD_COMPUTE_HMAC ((unsigned short)0x000C)
#define TOCMD_COMPUTE_HMAC_INIT ((unsigned short)0x0023)
#define TOCMD_COMPUTE_HMAC_UPDATE ((unsigned short)0x0024)
#define TOCMD_COMPUTE_HMAC_FINAL ((unsigned short)0x0025)
#define TOCMD_VERIFY_HMAC ((unsigned short)0x000D)
#define TOCMD_VERIFY_HMAC_INIT ((unsigned short)0x0026)
#define TOCMD_VERIFY_HMAC_UPDATE ((unsigned short)0x0027)
#define TOCMD_VERIFY_HMAC_FINAL ((unsigned short)0x0028)

/* AES (CBC) */
#define TOCMD_AESCBC_ENCRYPT ((unsigned short)0x000E)
#define TOCMD_AESCBC_DECRYPT ((unsigned short)0x000F)
#define TOCMD_AESCBC_IV_ENCRYPT ((unsigned short)0x0020)

/* CMAC */
#define TOCMD_COMPUTE_CMAC ((unsigned short)0x001C)
#define TOCMD_VERIFY_CMAC ((unsigned short)0x001D)

/* HASH: SHA256 */
#define TOCMD_SHA256 ((unsigned short)0x00A2)
#define TOCMD_SHA256_INIT ((unsigned short)0x00AA)
#define TOCMD_SHA256_UPDATE ((unsigned short)0x00AB)
#define TOCMD_SHA256_FINAL ((unsigned short)0x00AC)

/* MESSAGE: AES + HMAC */
#define TOCMD_SECURE_MESSAGE ((unsigned short)0x00A0)
#define TOCMD_UNSECURE_MESSAGE ((unsigned short)0x00A1)

/* ECIES Key Managment */
#define TOCMD_SET_REMOTE_PUBLIC_KEY ((unsigned short)0x00A3)
#define TOCMD_RENEW_ECC_KEYS ((unsigned short)0x00A4)
#define TOCMD_GET_PUBLIC_KEY ((unsigned short)0x00A5)
#define TOCMD_GET_UNSIGNED_PUBLIC_KEY ((unsigned short)0x002E)
#define TOCMD_RENEW_SHARED_KEYS ((unsigned short)0x00A6)
#define TOCMD_GET_KEY_FINGERPRINT ((unsigned short)0x0019)

/* TLS */
#define TOCMD_TLS_GET_RANDOM_AND_STORE ((unsigned short)0x0029)
#define TOCMD_TLS_RENEW_KEYS ((unsigned short)0x002A)
#define TOCMD_TLS_GET_MASTER_SECRET ((unsigned short)0x002B)
#define TOCMD_TLS_SET_SERVER_RANDOM ((unsigned short)0x002F)
#define TOCMD_TLS_SET_SERVER_EPUBLIC_KEY ((unsigned short) 0x002C)
#define TOCMD_TLS_RENEW_KEYS_ECDHE ((unsigned short) 0x002D)
#define TOCMD_TLS_COMPUTE_ECDH ((unsigned short)0x0030)
#define TOCMD_TLS_CALCULATE_FINISHED ((unsigned short)0x0031)

/* TLS optimized */
#define TOCMD_TLS_RESET ((unsigned short)0x00B6)
#define TOCMD_TLS_SET_MODE ((unsigned short)0x0042)
#define TOCMD_TLS_GET_CLIENT_HELLO ((unsigned short)0x0032)
#define TOCMD_TLS_HANDLE_HELLO_VERIFY_REQUEST ((unsigned short)0x0041)
#define TOCMD_TLS_HANDLE_SERVER_HELLO ((unsigned short)0x0033)
#define TOCMD_TLS_HANDLE_SERVER_CERTIFICATE_INIT ((unsigned short)0x0043)
#define TOCMD_TLS_HANDLE_SERVER_CERTIFICATE_UPDATE ((unsigned short)0x0044)
#define TOCMD_TLS_HANDLE_SERVER_CERTIFICATE_FINAL ((unsigned short)0x0045)
#define TOCMD_TLS_HANDLE_SERVER_KEY_EXCHANGE ((unsigned short)0x0035)
#define TOCMD_TLS_HANDLE_CERTIFICATE_REQUEST ((unsigned short)0x0036)
#define TOCMD_TLS_HANDLE_SERVER_HELLO_DONE ((unsigned short)0x0037)
#define TOCMD_TLS_GET_CERTIFICATE ((unsigned short)0x0038)
#define TOCMD_TLS_GET_CERTIFICATE_INIT ((unsigned short)0x00BD)
#define TOCMD_TLS_GET_CERTIFICATE_UPDATE ((unsigned short)0x00BE)
#define TOCMD_TLS_GET_CERTIFICATE_FINAL ((unsigned short)0x00BF)
#define TOCMD_TLS_GET_CLIENT_KEY_EXCHANGE ((unsigned short)0x0039)
#define TOCMD_TLS_GET_CERTIFICATE_VERIFY ((unsigned short)0x003A)
#define TOCMD_TLS_GET_CHANGE_CIPHER_SPEC ((unsigned short)0x003B)
#define TOCMD_TLS_GET_FINISHED ((unsigned short)0x003C)
#define TOCMD_TLS_HANDLE_CHANGE_CIPHER_SPEC ((unsigned short)0x003D)
#define TOCMD_TLS_HANDLE_FINISHED ((unsigned short)0x003E)
#define TOCMD_TLS_SECURE_MESSAGE ((unsigned short)0x003F)
#define TOCMD_TLS_SECURE_MESSAGE_INIT ((unsigned short)0x00B7)
#define TOCMD_TLS_SECURE_MESSAGE_UPDATE ((unsigned short)0x00B8)
#define TOCMD_TLS_SECURE_MESSAGE_FINAL ((unsigned short)0x00B9)
#define TOCMD_TLS_UNSECURE_MESSAGE ((unsigned short)0x0040)
#define TOCMD_TLS_UNSECURE_MESSAGE_INIT ((unsigned short)0x00BA)
#define TOCMD_TLS_UNSECURE_MESSAGE_UPDATE ((unsigned short)0x00BB)
#define TOCMD_TLS_UNSECURE_MESSAGE_FINAL ((unsigned short)0x00BC)

/* LoRa */
#define TOCMD_LORA_GET_APPEUI ((unsigned short)0x0108)
#define TOCMD_LORA_GET_DEVEUI ((unsigned short)0x0109)
#define TOCMD_LORA_COMPUTE_MIC ((unsigned short)0x010A)
#define TOCMD_LORA_ENCRYPT_PAYLOAD ((unsigned short)0x010B)
#define TOCMD_LORA_DECRYPT_JOIN ((unsigned short)0x010C)
#define TOCMD_LORA_COMPUTE_SHARED_KEYS ((unsigned short)0x010D)
#define TOCMD_LORA_GET_DEVADDR ((unsigned short)0x0110)

/* LoRa optimized */
#define TOCMD_LORA_GET_JOIN_REQUEST ((unsigned short)0x0100)
#define TOCMD_LORA_HANDLE_JOIN_ACCEPT ((unsigned short)0x0101)
#define TOCMD_LORA_SECURE_PHYPAYLOAD ((unsigned short)0x0102)
#define TOCMD_LORA_UNSECURE_PHYPAYLOAD ((unsigned short)0x0103)

/* Personalization */
#define TOCMD_SET_PRE_PERSONALIZATION_DATA ((unsigned short)0x0013)
#define TOCMD_SET_PERSONALIZATION_DATA ((unsigned short)0x0014)
#define TOCMD_SET_NEXT_STATE ((unsigned short)0x0015)
#define TOCMD_GET_STATE ((unsigned short)0x0016)

/* Lock */
#define TOCMD_LOCK ((unsigned short)0x0017)
#define TOCMD_UNLOCK ((unsigned short)0x0018)

/* Symmetric key Management */
#define TOCMD_SET_AES_KEY ((unsigned short)0x00A7)
#define TOCMD_SET_HMAC_KEY ((unsigned short)0x00A8)
#define TOCMD_SET_CMAC_KEY ((unsigned short)0x00A9)

/* Secure link */
#define TOCMD_SECLINK_ARC4 ((unsigned short)0xFF00)
#define TOCMD_SECLINK_ARC4_GET_IV ((unsigned short)0xFF01)
#define TOCMD_SECLINK_ARC4_GET_NEW_KEY ((unsigned short)0xFF04)
#define TOCMD_SECLINK_AESHMAC ((unsigned short)0xFF02)
#define TOCMD_SECLINK_AESHMAC_GET_IV ((unsigned short)0xFF03)
#define TOCMD_SECLINK_AESHMAC_GET_NEW_KEYS ((unsigned short)0xFF05)

/** @} */

/** @addtogroup consts
 * Constants
 * @{ */

#define TO_CMDHEAD_SIZE 5UL
#define TO_RSPHEAD_SIZE 4UL
#define TO_MAXSIZE 512UL
#define TO_INDEX_SIZE 1UL
#define TO_FORMAT_SIZE 1UL
#define TO_AES_BLOCK_SIZE 16UL
#define TO_INITIALVECTOR_SIZE TO_AES_BLOCK_SIZE
#define TO_AES_KEYSIZE 16UL
#define TO_HMAC_KEYSIZE 16UL
#define TO_HMAC_SIZE TO_SHA256_HASHSIZE
#define TO_HMAC_MINSIZE 10UL
#define TO_CMAC_KEYSIZE 16UL
#define TO_CMAC_SIZE TO_AES_BLOCK_SIZE
#define TO_CMAC_MIN_SIZE 4UL

#define TO_SHA256_HASHSIZE 32UL
#define TO_HASH_SIZE TO_SHA256_HASHSIZE

#define TO_CHALLENGE_SIZE 32UL

#define TO_SN_SIZE (TO_SN_CA_ID_SIZE+TO_SN_NB_SIZE)
#define TO_SN_CA_ID_SIZE 3UL
#define TO_SN_NB_SIZE 5UL

#define TO_PN_SIZE 12UL

#define TO_HW_VERSION_SIZE 2UL

#define TO_HWVERSION_SCB136I 01UL
#define TO_HWVERSION_EMU 0xFFFFUL

#define TO_SW_VERSION_SIZE 3UL

#define TO_CERTIFICATE_SIZE \
	(TO_SN_SIZE+TO_ECC_PUB_KEYSIZE+TO_SIGNATURE_SIZE)
#define TO_CERT_PRIVKEY_SIZE 32UL
#define TO_ECC_PRIV_KEYSIZE TO_CERT_PRIVKEY_SIZE
#define TO_ECC_PUB_KEYSIZE (2*TO_ECC_PRIV_KEYSIZE)
#define TO_SIGNATURE_SIZE TO_ECC_PUB_KEYSIZE


#define TO_CERT_GENERALIZED_TIME_SIZE  15UL /* YYYYMMDDHHMMSSZ */
#define TO_CERT_DATE_SIZE ((TO_CERT_GENERALIZED_TIME_SIZE - 1) / 2)
#define TO_CERT_SUBJECT_PREFIX_SIZE 15UL
#define TO_SHORTV2_CERT_SIZE (TO_CERTIFICATE_SIZE + \
		TO_CERT_DATE_SIZE)

#define TO_REMOTE_CERTIFICATE_SIZE (TO_SN_SIZE+TO_ECC_PUB_KEYSIZE)
#define TO_REMOTE_CAID_SIZE TO_SN_CA_ID_SIZE

#define TO_CERT_SUBJECT_CN_MAXSIZE 64UL

#define TO_KEYTYPE_SIZE TO_SN_CA_ID_SIZE
#define TO_CA_PUBKEY_SIZE TO_ECC_PUB_KEYSIZE
#define TO_CA_PUBKEY_CAID_SIZE TO_SN_CA_ID_SIZE

#define TO_KEY_FINGERPRINT_SIZE 3UL

#define TO_TIMESTAMP_SIZE 4UL
#define TO_TLS_RANDOM_SIZE (TO_TIMESTAMP_SIZE + 28UL)
#define TO_TLS_MASTER_SECRET_SIZE 48UL
#define TO_TLS_SERVER_PARAMS_SIZE 69UL
#define TO_TLS_HMAC_KEYSIZE 32UL
#define TO_TLS_FINISHED_SIZE 12UL
#define TO_TLS_CLIENT_HELLO_MAXSIZE (TO_TLS_HANDSHAKE_HEADER_SIZE + 144UL)
#define TO_TLS_SERVER_HELLO_DONE_SIZE TO_TLS_HANDSHAKE_HEADER_SIZE
#define TO_TLS_SERVER_CERTIFICATE_INIT_SIZE (TO_TLS_HANDSHAKE_HEADER_SIZE + 3UL)
#define TO_TLS_CLIENT_CERTIFICATE_INIT_SIZE (TO_TLS_HANDSHAKE_HEADER_SIZE + 6UL)
#define TO_TLS_CLIENT_CERTIFICATE_SIZE (TO_TLS_HANDSHAKE_HEADER_SIZE + 422UL)
#define TO_TLS_CLIENT_KEY_EXCHANGE_MAXSIZE (TO_TLS_HANDSHAKE_HEADER_SIZE + 66UL)
#define TO_TLS_CERTIFICATE_VERIFY_MAXSIZE (TO_TLS_HANDSHAKE_HEADER_SIZE + 76UL)
#define TO_TLS_CHANGE_CIPHER_SPEC_SIZE 1UL
#define TO_TLS_FINISHED_PAYLOAD_SIZE (TO_TLS_HANDSHAKE_HEADER_SIZE + 12UL)
#ifdef TO_ENABLE_DTLS
#define TO_TLS_HEADER_SIZE 13UL
#define TO_TLS_HANDSHAKE_HEADER_SIZE 12UL
#else
#define TO_TLS_HEADER_SIZE 5UL
#define TO_TLS_HANDSHAKE_HEADER_SIZE 4UL
#endif

typedef enum TO_tls_mode_e {
	TO_TLS_MODE_UNKNOWN = 0,
	TO_TLS_MODE_TLS = 0x10,
	TO_TLS_MODE_TLS_1_0 = TO_TLS_MODE_TLS | 0x1,
	TO_TLS_MODE_TLS_1_1 = TO_TLS_MODE_TLS | 0x2,
	TO_TLS_MODE_TLS_1_2 = TO_TLS_MODE_TLS | 0x3,
	TO_TLS_MODE_DTLS = 0x20,
	TO_TLS_MODE_DTLS_1_0 = TO_TLS_MODE_DTLS | 0x1,
	TO_TLS_MODE_DTLS_1_1 = TO_TLS_MODE_DTLS | 0x2,
	TO_TLS_MODE_DTLS_1_2 = TO_TLS_MODE_DTLS | 0x3,
} TO_tls_mode_t;

#define TO_ARC4_KEY_SIZE 16UL
#define TO_ARC4_INITIALVECTOR_SIZE 16UL

#define TO_I2CADDR_SIZE 1UL

#define TO_CRC_SIZE 2UL

#define TO_PPERSO_ID_SIZE 4UL
#define TO_PPERSO_SUBID_SIZE 1UL
#define TO_PPERSO_TAG_SIZE 4UL

#define TO_LORA_PHYPAYLOAD_MINSIZE 10UL
#define TO_LORA_MHDR_SIZE 1UL
#define TO_LORA_APPEUI_SIZE 8UL
#define TO_LORA_DEVEUI_SIZE 8UL
#define TO_LORA_DEVADDR_SIZE 4UL
#define TO_LORA_DEVNONCE_SIZE 2UL
#define TO_LORA_APPNONCE_SIZE 3UL
#define TO_LORA_NETID_SIZE 3UL
#define TO_LORA_MIC_SIZE 4UL
#define TO_LORA_FCTRL_SIZE 1UL
#define TO_LORA_FCNT_SIZE 4UL
#define TO_LORA_APPKEY_SIZE 16UL
#define TO_LORA_JOINREQUEST_SIZE (TO_LORA_MHDR_SIZE + \
                                     TO_LORA_APPEUI_SIZE + \
                                     TO_LORA_DEVEUI_SIZE + \
                                     TO_LORA_DEVNONCE_SIZE + \
                                     TO_LORA_MIC_SIZE)

#define TO_I2C_SEND_MSTIMEOUT TO_I2C_MSTIMEOUT
#define TO_I2C_RECV_MSTIMEOUT TO_I2C_MSTIMEOUT
/* 5s for any I2C transaction */
#define TO_I2C_MSTIMEOUT 5000UL
/* 10s waiting Start Condition to send response */
#define TO_I2C_RESPONSE_MSTIMEOUT 10000UL
/* 10s waiting Start Condition to send Error */
#define TO_I2C_ERROR_MSTIMEOUT 10000UL

#define TO_STATUS_PIO_ENABLE 0x80
#define TO_STATUS_PIO_READY_LEVEL_MASK 0x01
#define TO_STATUS_PIO_HIGH_OPENDRAIN_MASK 0x02
#define TO_STATUS_PIO_IDLE_HZ_MASK 0x04

#define TO_STATE_PREPERSO ((unsigned char)0xA3)
#define TO_STATE_PERSO ((unsigned char)0x52)
#define TO_STATE_NORMAL ((unsigned char)0x00)
#define TO_STATE_LOCKED ((unsigned char)0xFF)

/** @} */

/** @addtogroup certs
 * @{ */

/*
 * Certificates Format
 */

#define TOCERTF_STANDALONE ((unsigned char)0x00)
#define TOCERTF_SHORT ((unsigned char)0x01)
#define TOCERTF_X509 ((unsigned char)0x02)
#define TOCERTF_SHORT_V2 ((unsigned char)0x03)
#define TOCERTF_VALIDITY_DATE_SIZE 7UL
#define TOCERTF_SUBJECT_NAME_SIZE 15UL

/**
 * Certificates formats
 *
 * - TO_CERTIFICATE_X509 is used for Secure Element and remote certificate
 *   verification
 * - TO_CERTIFICATE_STANDALONE is only used for remote certificate
 *   verification
 * - TO_CERTIFICATE_SHORT is only used for Secure Element certificates
 */
enum TO_certificate_format_e {
	TO_CERTIFICATE_STANDALONE = TOCERTF_STANDALONE,
	TO_CERTIFICATE_SHORT = TOCERTF_SHORT,
	TO_CERTIFICATE_X509 = TOCERTF_X509,
	TO_CERTIFICATE_SHORT_V2 = TOCERTF_SHORT_V2,
};
typedef enum TO_certificate_format_e TO_certificate_format_t;

/**
 * Standalone certificate structure
 */
struct TO_cert_standalone_s {
	uint8_t ca_id[TO_SN_CA_ID_SIZE]; /**< Certificate Authority ID */
	uint8_t serial_number[TO_SN_NB_SIZE]; /**< SE serial number */
	uint8_t public_key[TO_ECC_PUB_KEYSIZE]; /**< Public key */
	uint8_t signature[TO_SIGNATURE_SIZE]; /**< Certificate signature */
};
typedef struct TO_cert_standalone_s TO_cert_standalone_t;

/**
 * Short certificate structure
 */
struct TO_cert_short_s {
	uint8_t ca_id[TO_SN_CA_ID_SIZE]; /**< Certificate Authority ID */
	uint8_t serial_number[TO_SN_NB_SIZE]; /**< SE serial number */
	uint8_t public_key[TO_ECC_PUB_KEYSIZE]; /**< Public key */
	uint8_t signature[TO_SIGNATURE_SIZE]; /**< Certificate signature */
};
typedef struct TO_cert_short_s TO_cert_short_t;

/**
 * Short v2 certificate structure
 */
struct TO_cert_short_v2_s {
	uint8_t ca_id[TO_SN_CA_ID_SIZE]; /**< Certificate Authority ID */
	uint8_t serial_number[TO_SN_NB_SIZE]; /**< SE serial number */
	uint8_t date[TOCERTF_VALIDITY_DATE_SIZE]; /**< Validity date
						    (Zulu date (UTC)) */
	uint8_t public_key[TO_ECC_PUB_KEYSIZE]; /**< Public key */
	uint8_t signature[TO_SIGNATURE_SIZE]; /**< Certificate signature */
};
typedef struct TO_cert_short_v2_s TO_cert_short_v2_t;

/**
 * CA index to enable Authority Key Identifier based CA detection
 */
#define TO_CA_IDX_AUTO 0xFF

/** @} */

#endif
