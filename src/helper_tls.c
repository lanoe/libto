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
 *
 * Secure Element helpers, besed on Secure Element APIs to simplify complex processes.
 */

#include <TO.h>
#include <TO_helper.h>
#include <core.h>

#ifndef TO_DISABLE_TLS_HELPER

/* Dependency checks */
#ifdef TO_DISABLE_TLS_OPTIMIZED
#error TLS optimized APIs must be enabled for TLS helper
#endif

#include <TO.h>
#include <TO_helper.h>
#include <TO_endian.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define _TLS_HANDLE_SERVER_CERTIFICATE_UPDATE_SIZE (MIN(TO_MAXSIZE, TO_LIB_INTERNAL_IO_BUFFER_SIZE) - TO_CMDHEAD_SIZE)

int TO_helper_tls_handle_server_certificate(const uint8_t *server_certificate,
		const uint32_t server_certificate_len)
{
	uint32_t offset = 0;
	int ret;

	ret = TO_tls_handle_server_certificate_init(server_certificate + offset);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}
	offset += TO_TLS_SERVER_CERTIFICATE_INIT_SIZE;

	while (offset < server_certificate_len) {
		uint32_t len = MIN(_TLS_HANDLE_SERVER_CERTIFICATE_UPDATE_SIZE, server_certificate_len - offset);
		ret = TO_tls_handle_server_certificate_update(server_certificate + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR;
		}
		offset += len;
	}

	ret = TO_tls_handle_server_certificate_final();
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	return TO_OK;
}

int TO_helper_tls_get_certificate(uint8_t *certificate,
		uint16_t *certificate_len)
{
	uint16_t offset = 0;
	uint16_t len;
	int ret;

	ret = TO_tls_get_certificate_init(certificate + offset);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}
	offset += TO_TLS_CLIENT_CERTIFICATE_INIT_SIZE;

	do {
		ret = TO_tls_get_certificate_update(certificate + offset, &len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR;
		}
		offset += len;
	} while (len > 0);

	ret = TO_tls_get_certificate_final();
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	*certificate_len = offset;

	return TO_OK;
}

#define _TLS_SECURE_MESSAGE_UPDATE_SIZE (MIN(TO_MAXSIZE, TO_LIB_INTERNAL_IO_BUFFER_SIZE) - TO_CMDHEAD_SIZE)

int TO_helper_tls_secure_message(const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t* data, const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	uint32_t offset = 0;
	uint16_t len;
	int ret;

	*cryptogram_len = 0;

	ret = TO_tls_secure_message_init(header, initial_vector);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	while (data_len - offset >= TO_AES_BLOCK_SIZE) {
		len = MIN(_TLS_SECURE_MESSAGE_UPDATE_SIZE, data_len - offset);
		len -= len % TO_AES_BLOCK_SIZE;
		ret = TO_tls_secure_message_update(data + offset, len, cryptogram + offset);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR;
		}
		offset += len;
		*cryptogram_len += len;
	}

	ret = TO_tls_secure_message_final(data + offset, data_len - offset, cryptogram + offset, &len);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	*cryptogram_len += len;

	return TO_OK;
}

#define _TLS_UNSECURE_MESSAGE_UPDATE_SIZE (MIN(TO_MAXSIZE, TO_LIB_INTERNAL_IO_BUFFER_SIZE) - TO_CMDHEAD_SIZE)

int TO_helper_tls_unsecure_message(const uint8_t header[TO_TLS_HEADER_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	uint32_t offset = 0;
	int ret;

	*data_len = 0;

	ret = TO_tls_unsecure_message_init(cryptogram_len, header, initial_vector,
			cryptogram + cryptogram_len - 2 * TO_AES_BLOCK_SIZE,
			cryptogram + cryptogram_len - TO_AES_BLOCK_SIZE);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	while (offset < cryptogram_len) {
		uint16_t olen;
		uint16_t len = MIN(_TLS_UNSECURE_MESSAGE_UPDATE_SIZE, cryptogram_len - offset);
		len -= len % TO_AES_BLOCK_SIZE;
		ret = TO_tls_unsecure_message_update(cryptogram + offset, len, data + offset, &olen);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR;
		}
		offset += len;
		*data_len += olen;
	}

	ret = TO_tls_unsecure_message_final();
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR;
	}

	return TO_OK;
}

#ifdef TO_ENABLE_DTLS
#define _TLS_MAJOR 254
#define _TLS_MINOR 253
#define _TLS_EPOCH_MAX 1
#define _TLS_TIMEOUT_MIN 1000
#define _TLS_TIMEOUT_MAX 60000
/* Fragment maximal size in bytes (not including headers) */
#define _TLS_FRAGMENT_MAXSIZE 256
#else
#define _TLS_MAJOR 3
#define _TLS_MINOR 3
#endif
#ifndef TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE
#define TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE 1024
#endif
#ifndef TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE
#define TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE 2048
#endif
#if !defined(TO_ENABLE_DTLS) || defined(TO_DISABLE_DTLS_RETRANSMISSION)
#undef TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE
#define TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE
#endif
#define _TLS_SESSION_ID_MAXSIZE 32

typedef enum {
	_TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC = 0x14,
	_TLS_RECORD_TYPE_ALERT = 0x15,
	_TLS_RECORD_TYPE_HANDSHAKE = 0x16,
	_TLS_RECORD_TYPE_APPLICATION_DATA = 0x17,
} _tls_record_type_t;

#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
typedef struct {
	uint8_t encryption;
	uint8_t type;
#ifdef TO_ENABLE_DTLS
	uint16_t epoch;
#endif
} _tls_flight_header_t;
#define TLS_FLIGHT_HEADER_SIZE sizeof(_tls_flight_header_t)
#else
#define TLS_FLIGHT_HEADER_SIZE 0
#endif

typedef enum {
	_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
	_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025,
} _tls_cipher_suite_t;

typedef enum _tls_handshake_type_e {
	_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01,
	_HANDSHAKE_TYPE_SERVER_HELLO = 0x02,
#ifdef TO_ENABLE_DTLS
	_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST = 0x03,
#endif
	_HANDSHAKE_TYPE_CERTIFICATE = 0x0b,
	_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 0x0c,
	_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 0x0d,
	_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 0x0e,
	_HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0f,
	_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 0x10,
	_HANDSHAKE_TYPE_FINISHED = 0x14,
} _tls_handshake_type_t;

typedef enum _tls_alert_level_e {
	_ALERT_LEVEL_WARNING = 0x01,
	_ALERT_LEVEL_FATAL = 0x02,
} _tls_alert_level_t;

typedef enum _tls_alert_desc_e {
	_ALERT_DESC_CLOSE_NOTIFY = 0,
	_ALERT_DESC_UNEXPECTED_MESSAGE = 10,
	_ALERT_DESC_BAD_RECORD_MAC = 20,
	_ALERT_DESC_DECRYPTION_FAILED_RESERVED = 21,
	_ALERT_DESC_RECORD_OVERFLOW = 22,
	_ALERT_DESC_DECOMPRESSION_FAILURE = 30,
	_ALERT_DESC_HANDSHAKE_FAILURE = 40,
	_ALERT_DESC_NO_CERTIFICATE_RESERVED = 41,
	_ALERT_DESC_BAD_CERTIFICATE = 42,
	_ALERT_DESC_UNSUPPORTED_CERTIFICATE = 43,
	_ALERT_DESC_CERTIFICATE_REVOKED = 44,
	_ALERT_DESC_CERTIFICATE_EXPIRED = 45,
	_ALERT_DESC_CERTIFICATE_UNKNOWN = 46,
	_ALERT_DESC_ILLEGAL_PARAMETER = 47,
	_ALERT_DESC_UNKNOWN_CA = 48,
	_ALERT_DESC_ACCESS_DENIED = 49,
	_ALERT_DESC_DECODE_ERROR = 50,
	_ALERT_DESC_DECRYPT_ERROR = 51,
	_ALERT_DESC_EXPORT_RESTRICTION_RESERVED = 60,
	_ALERT_DESC_PROTOCOL_VERSION = 70,
	_ALERT_DESC_INSUFFICIENT_SECURITY = 71,
	_ALERT_DESC_INTERNAL_ERROR = 80,
	_ALERT_DESC_USER_CANCELED = 90,
	_ALERT_DESC_NO_RENEGOTIATION = 100,
	_ALERT_DESC_UNSUPPORTED_EXTENSION = 110,
} _tls_alert_desc_t;

typedef enum _tls_state_e {
	_STATE_FLIGHT_1 = 0x0100,
	_STATE_CLIENT_HELLO = _STATE_FLIGHT_1 | _HANDSHAKE_TYPE_CLIENT_HELLO,
	_STATE_FLIGHT_1_INIT = _STATE_CLIENT_HELLO,
#ifdef TO_ENABLE_DTLS
	_STATE_FLIGHT_2 = 0x0200,
	_STATE_SERVER_HELLO_VERIFY_REQUEST = _STATE_FLIGHT_2 | _HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST,
	_STATE_FLIGHT_2_INIT = _STATE_SERVER_HELLO_VERIFY_REQUEST,
	_STATE_FLIGHT_3 = 0x0400,
	_STATE_CLIENT_HELLO_WITH_COOKIE = _STATE_FLIGHT_3 | _HANDSHAKE_TYPE_CLIENT_HELLO,
	_STATE_FLIGHT_3_INIT = _STATE_CLIENT_HELLO_WITH_COOKIE,
#endif
	_STATE_FLIGHT_4 = 0x0800,
	_STATE_SERVER_HELLO = _STATE_FLIGHT_4 | _HANDSHAKE_TYPE_SERVER_HELLO,
	_STATE_FLIGHT_4_INIT = _STATE_SERVER_HELLO,
	_STATE_SERVER_CERTIFICATE = _STATE_FLIGHT_4 | _HANDSHAKE_TYPE_CERTIFICATE,
	_STATE_SERVER_KEY_EXCHANGE = _STATE_FLIGHT_4 | _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
	_STATE_SERVER_CERTIFICATE_REQUEST = _STATE_FLIGHT_4 | _HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
	_STATE_SERVER_HELLO_DONE = _STATE_FLIGHT_4 | _HANDSHAKE_TYPE_SERVER_HELLO_DONE,
	_STATE_FLIGHT_5 = 0x1000,
	_STATE_CLIENT_CERTIFICATE = _STATE_FLIGHT_5 | _HANDSHAKE_TYPE_CERTIFICATE,
	_STATE_FLIGHT_5_INIT = _STATE_CLIENT_CERTIFICATE,
	_STATE_CLIENT_KEY_EXCHANGE = _STATE_FLIGHT_5 | _HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
	_STATE_FLIGHT_5_INIT_NO_CLIENT_AUTH = _STATE_CLIENT_KEY_EXCHANGE,
	_STATE_CLIENT_CERTIFICATE_VERIFY = _STATE_FLIGHT_5 | _HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
	_STATE_CLIENT_CHANGE_CIPHER_SPEC = _STATE_FLIGHT_5 | 0xff,
	_STATE_CLIENT_FINISHED = _STATE_FLIGHT_5 | _HANDSHAKE_TYPE_FINISHED,
	_STATE_FLIGHT_6 = 0x2000,
	_STATE_SERVER_CHANGE_CIPHER_SPEC = _STATE_FLIGHT_6 | 0xff,
	_STATE_FLIGHT_6_INIT = _STATE_SERVER_CHANGE_CIPHER_SPEC,
	_STATE_SERVER_FINISHED = _STATE_FLIGHT_6 | _HANDSHAKE_TYPE_FINISHED,
	_STATE_HANDSHAKE_DONE = 0x8000,
	_STATE_HANDSHAKE_FAILED = 0x8001,
} _tls_state_t;;

typedef struct _tls_ctx_s {
	uint8_t *pbuf;
	uint8_t rx;
	uint32_t flight_offset;
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
	uint8_t flight_buf[TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE];
#else
	uint8_t *flight_buf;
#endif
	uint8_t buf[TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE];
	uint32_t cache_offs;
	uint32_t cache_len;
	_tls_record_type_t cache_type;
	uint8_t encryption;
	uint8_t decryption;
	uint8_t auth_client;
	uint8_t abbriviated_handshake;
	uint8_t client_session_id_len;
	uint8_t client_session_id[_TLS_SESSION_ID_MAXSIZE];
	_tls_cipher_suite_t cipher_suite;
	_tls_state_t state;
#ifdef TO_ENABLE_DTLS
	uint16_t epoch;
	uint64_t sequence_number_up[_TLS_EPOCH_MAX + 1];
	uint64_t sequence_number_down[_TLS_EPOCH_MAX + 1];
	uint16_t timeout;
	uint32_t record_cache_offs;
	uint32_t record_cache_len;
#endif
} _tls_ctx_t;

static _tls_ctx_t _tls_ctx;

#ifdef TO_DEBUG
static void _tls_print_alert(_tls_alert_level_t level, _tls_alert_desc_t desc)
{
	const char *level_str;
	const char *desc_str;

	switch (level) {
		case _ALERT_LEVEL_WARNING:
			level_str = "Warning";
			break;
		case _ALERT_LEVEL_FATAL:
			level_str = "Fatal";
			break;
		default:
			level_str = "Unknown alert level";
			break;
	}

	switch (desc) {
		case _ALERT_DESC_CLOSE_NOTIFY:
			desc_str = "close notify";
			break;
		case _ALERT_DESC_UNEXPECTED_MESSAGE:
			desc_str = "unexpected message";
			break;
		case _ALERT_DESC_BAD_RECORD_MAC:
			desc_str = "bad record mac";
			break;
		case _ALERT_DESC_DECRYPTION_FAILED_RESERVED:
			desc_str = "decryption failed reserved";
			break;
		case _ALERT_DESC_RECORD_OVERFLOW:
			desc_str = "record overflow";
			break;
		case _ALERT_DESC_DECOMPRESSION_FAILURE:
			desc_str = "decompression failure";
			break;
		case _ALERT_DESC_HANDSHAKE_FAILURE:
			desc_str = "handshake failure";
			break;
		case _ALERT_DESC_NO_CERTIFICATE_RESERVED:
			desc_str = "no certificate reserved";
			break;
		case _ALERT_DESC_BAD_CERTIFICATE:
			desc_str = "bad certificate";
			break;
		case _ALERT_DESC_UNSUPPORTED_CERTIFICATE:
			desc_str = "unsupported certificate";
			break;
		case _ALERT_DESC_CERTIFICATE_REVOKED:
			desc_str = "certificate revoked";
			break;
		case _ALERT_DESC_CERTIFICATE_EXPIRED:
			desc_str = "certificate expired";
			break;
		case _ALERT_DESC_CERTIFICATE_UNKNOWN:
			desc_str = "certificate unknown";
			break;
		case _ALERT_DESC_ILLEGAL_PARAMETER:
			desc_str = "illegal parameter";
			break;
		case _ALERT_DESC_UNKNOWN_CA:
			desc_str = "unknown ca";
			break;
		case _ALERT_DESC_ACCESS_DENIED:
			desc_str = "access denied";
			break;
		case _ALERT_DESC_DECODE_ERROR:
			desc_str = "decode error";
			break;
		case _ALERT_DESC_DECRYPT_ERROR:
			desc_str = "decrypt error";
			break;
		case _ALERT_DESC_EXPORT_RESTRICTION_RESERVED:
			desc_str = "export restriction reserved";
			break;
		case _ALERT_DESC_PROTOCOL_VERSION:
			desc_str = "protocol version";
			break;
		case _ALERT_DESC_INSUFFICIENT_SECURITY:
			desc_str = "insufficient security";
			break;
		case _ALERT_DESC_INTERNAL_ERROR:
			desc_str = "internal error";
			break;
		case _ALERT_DESC_USER_CANCELED:
			desc_str = "user canceled";
			break;
		case _ALERT_DESC_NO_RENEGOTIATION:
			desc_str = "no renegotiation";
			break;
		case _ALERT_DESC_UNSUPPORTED_EXTENSION:
			desc_str = "unsupported extension";
			break;
		default:
			desc_str = "unknown description";
			break;
	}

	FPRINTF(stdout, "TLS alert:\n%s: %s\n", level_str, desc_str);
#else
static void _tls_print_alert(_tls_alert_level_t level __attribute__((unused)),
		_tls_alert_desc_t desc __attribute__((unused)))
{
#endif
}

static int _tls_send(_tls_record_type_t _type, uint8_t *_data, uint32_t _len,
#ifdef TO_ENABLE_DTLS
		uint16_t epoch,
#endif
		uint8_t encryption, void *_ctx,
		TO_helper_tls_handshake_send_func send_func)
{
	uint8_t _offset = 0;
	int32_t _ret;
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
	_tls_flight_header_t *_flight_hdr = (_tls_flight_header_t*)_data;
#endif
	uint32_t to_send_len;
	uint32_t frag_offset = 0;

#ifdef TO_ENABLE_DTLS
	if (_type == _TLS_RECORD_TYPE_HANDSHAKE) {
		to_send_len = _len - TO_TLS_HANDSHAKE_HEADER_SIZE;
	} else
#endif
	{
		to_send_len = _len;
	}

#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
	/* Save record parameters in source buffer */
	_flight_hdr->encryption = encryption;
	_flight_hdr->type = _type;
#ifdef TO_ENABLE_DTLS
	_flight_hdr->epoch = epoch;
#endif
#endif

	/* TLS header */
	_tls_ctx.buf[_offset++] = _type;
	_tls_ctx.buf[_offset++] = _TLS_MAJOR;
	_tls_ctx.buf[_offset++] = _TLS_MINOR;
#ifdef TO_ENABLE_DTLS
	_tls_ctx.buf[_offset++] = epoch >> 8;
	_tls_ctx.buf[_offset++] = epoch & 0xff;
	/* Skip sequence */
	_offset += 6;
#endif
	*((uint16_t*)(_tls_ctx.buf + _offset)) = htobe16(_len);
	_offset += sizeof(uint16_t);

	do {
		uint32_t frag_len;
		uint32_t len;
#ifdef TO_ENABLE_DTLS
		uint16_t __offset = _offset;

		__offset -= 6 + sizeof(uint16_t);
		if (_type == _TLS_RECORD_TYPE_HANDSHAKE) {
			frag_len = MIN(_TLS_FRAGMENT_MAXSIZE, to_send_len);
			len = frag_len + TO_TLS_HANDSHAKE_HEADER_SIZE;
		} else
#endif
		{
			frag_len = to_send_len;
			len = frag_len;
		}

		/* Protect buffer overflow */
		if (_offset + len > TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE) {
			FPRINTF(stderr, "%s: IO buffer too small, %lu bytes needed\n", __func__,
					(unsigned long int)(_offset + len));
			return TO_ERROR;
		}

		/* Write TLS header */
#ifdef TO_ENABLE_DTLS
		_tls_ctx.buf[__offset++] = (_tls_ctx.sequence_number_up[epoch] >> 40) & 0xff;
		_tls_ctx.buf[__offset++] = (_tls_ctx.sequence_number_up[epoch] >> 32) & 0xff;
		_tls_ctx.buf[__offset++] = (_tls_ctx.sequence_number_up[epoch] >> 24) & 0xff;
		_tls_ctx.buf[__offset++] = (_tls_ctx.sequence_number_up[epoch] >> 16) & 0xff;
		_tls_ctx.buf[__offset++] = (_tls_ctx.sequence_number_up[epoch] >>  8) & 0xff;
		_tls_ctx.buf[__offset++] = (_tls_ctx.sequence_number_up[epoch]      ) & 0xff;
		++_tls_ctx.sequence_number_up[epoch];
		*((uint16_t*)(_tls_ctx.buf + __offset)) = htobe16(len);
		__offset += sizeof(uint16_t);
#endif

#ifdef TO_ENABLE_DTLS
		if (_type == _TLS_RECORD_TYPE_HANDSHAKE) {
			uint32_t tmp32 = 0;

#ifndef TO_DISABLE_DTLS_RETRANSMISSION
			/* Copy TLS handshake header */
			secure_memcpy(_tls_ctx.buf + _offset, _data + TLS_FLIGHT_HEADER_SIZE, TO_TLS_HANDSHAKE_HEADER_SIZE);
#endif

			/* Rewrite TLS handshake header */
			tmp32 = htobe32(frag_offset);
			secure_memcpy(_tls_ctx.buf + _offset + TO_TLS_HANDSHAKE_HEADER_SIZE - 3 * 2, ((uint8_t*)&tmp32) + 1, 3);
			tmp32 = htobe32(frag_len);
			secure_memcpy(_tls_ctx.buf + _offset + TO_TLS_HANDSHAKE_HEADER_SIZE - 3, ((uint8_t*)&tmp32) + 1, 3);

			/* Copy data */
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
			secure_memcpy(
#else
			secure_memmove(
#endif
					_tls_ctx.buf + _offset + TO_TLS_HANDSHAKE_HEADER_SIZE,
					_data + TLS_FLIGHT_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE + frag_offset,
					frag_len);
		} else
#endif
		{
			/* Copy data */
			secure_memmove(_tls_ctx.buf + _offset, _data + TLS_FLIGHT_HEADER_SIZE, len);
		}

		FPRINTF(stdout, "%s: Send buffer:\n", __func__);
		DUMP_BUFFER(_tls_ctx.buf, _offset + len);

		if (encryption
		 && _type != _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC) {
			uint16_t tmp_len;
			/* Move data to allow using same buffer as source and destination */
			secure_memmove(_tls_ctx.buf + TO_AES_BLOCK_SIZE, _tls_ctx.buf, TO_TLS_HEADER_SIZE + len);
			int ret = TO_helper_tls_secure_message(_tls_ctx.buf + TO_AES_BLOCK_SIZE,
			                                       _tls_ctx.buf + TO_AES_BLOCK_SIZE +_offset, len,
			                                       _tls_ctx.buf + _offset,
			                                       _tls_ctx.buf + _offset + TO_INITIALVECTOR_SIZE,
			                                       &tmp_len);
			if (ret != TO_OK) {
				FPRINTF(stderr, "%s: Failed to secure message\n", __func__);
				return TO_ERROR;
			}
			len = TO_INITIALVECTOR_SIZE + tmp_len;
			/* Rewrite header */
			*((uint16_t*)(_tls_ctx.buf + _offset - sizeof(uint16_t))) = htobe16(len);

			FPRINTF(stdout, "%s: Encrypted buffer:\n", __func__);
			DUMP_BUFFER(_tls_ctx.buf, TO_TLS_HEADER_SIZE + len);
		}

		/* Send to network */
		_ret = send_func(_ctx, _tls_ctx.buf, _offset + len);
		if (_ret != TO_OK) {
			FPRINTF(stderr, "%s: Failed to send %lu bytes\n", __func__,
					(unsigned long int)(_offset + len));
			return TO_ERROR;
		}

		frag_offset += frag_len;
		to_send_len -= frag_len;
	} while (to_send_len > 0);

	return TO_OK;
}

static int _tls_send_alert(_tls_alert_level_t level, _tls_alert_desc_t desc,
		void *ctx, TO_helper_tls_handshake_send_func send_func)
{
	int ret = TO_OK;
	uint8_t offset = TLS_FLIGHT_HEADER_SIZE;

	*(_tls_ctx.flight_buf + offset++) = level;
	*(_tls_ctx.flight_buf + offset++) = desc;

	ret = _tls_send(_TLS_RECORD_TYPE_ALERT, _tls_ctx.flight_buf,
					offset,
#ifdef TO_ENABLE_DTLS
					_tls_ctx.epoch,
#endif
					_tls_ctx.encryption, ctx, send_func);
	if (ret != TO_OK) {
		FPRINTF(stderr, "%s: Failed to send %u bytes\n", __func__, offset);
		return TO_ERROR;
	}

	return TO_OK;
}

/* max_len parameter is only for application data partial read */
static int _tls_receive(_tls_record_type_t *_type, uint8_t *_data, uint32_t _data_size,
		uint32_t *_len, uint32_t max_len, uint8_t decryption, int32_t timeout,
		void *_ctx, TO_helper_tls_handshake_receive_func receive_func)
{
	int ret = TO_OK;
	uint8_t _offset = 0;
	int32_t _ret;
	uint32_t read_len;
	uint32_t total_read_len = 0;
	uint32_t len;
#ifdef TO_ENABLE_DTLS
	uint16_t epoch;
	uint64_t seq = 0;
#endif

	if (_tls_ctx.cache_len != 0
	 && *_type == _tls_ctx.cache_type) {
		if (_tls_ctx.cache_len > _data_size - TO_TLS_HEADER_SIZE) {
			FPRINTF(stderr, "%s: IO buffer too small, %lu bytes needed\n", __func__,
					(unsigned long int)(_tls_ctx.cache_len));
			return TO_ERROR;
		}
		secure_memmove(_data + TO_TLS_HEADER_SIZE, _data + _tls_ctx.cache_offs, _tls_ctx.cache_len);
		len = _tls_ctx.cache_len;
		_tls_ctx.cache_len = 0;
		_offset = TO_TLS_HEADER_SIZE;
		goto cache_check;
	}

#ifdef TO_ENABLE_DTLS
	if (_tls_ctx.record_cache_len != 0) {
		if (_tls_ctx.record_cache_len > _data_size) {
			FPRINTF(stderr, "%s: IO buffer too small, %lu bytes needed\n", __func__,
					(unsigned long int)(_tls_ctx.record_cache_len));
			return TO_ERROR;
		}
		secure_memmove(_data, _data + _tls_ctx.record_cache_offs, _tls_ctx.record_cache_len);
		read_len = _tls_ctx.record_cache_len;
		_tls_ctx.record_cache_len = 0;
	} else
#endif
	{
		/**
		 * Read length is protocol dependent.
		 * Datagrams need to be read fully, and connected protocols as TCP can be
		 * read by chunks (header, then message).
		 * We assume that DTLS will be used with UDP, but it needs to be adapted
		 * if using another datagram protocol.
		 */
#ifdef TO_ENABLE_DTLS
		read_len = TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE;
#else
		read_len = TO_TLS_HEADER_SIZE;
#endif
		read_len = MIN(read_len, _data_size);

		/* Receive header from network */
		if ((_ret = receive_func(_ctx, _data, read_len, &read_len, timeout)) != TO_OK) {
			FPRINTF(stderr, "%s: Failed to receive data\n", __func__);
			return _ret;
		}
	}

	/* Check read length */
	if (read_len < TO_TLS_HEADER_SIZE) {
		FPRINTF(stderr, "%s: Failed to receive enough data\n", __func__);
		return TO_ERROR;
	}

	total_read_len = read_len - TO_TLS_HEADER_SIZE;

	/* Type */
	*_type = (_tls_record_type_t)_data[_offset++];

#ifdef TO_ENABLE_DTLS
	/* HelloVerifyRequest(0x03) minor is always 255 */
	if (*_type == _TLS_RECORD_TYPE_HANDSHAKE && _data[TO_TLS_HEADER_SIZE] == 0x03) {
		_data[_offset + 1] = _TLS_MINOR;
	}
#endif

	/* Verify version */
	if (_data[_offset] != _TLS_MAJOR || _data[_offset + 1] != _TLS_MINOR) {
		FPRINTF(stderr, "%s: Bad TLS version %u:%u, expected %u:%u\n",
				__func__, _data[_offset], _data[_offset + 1], _TLS_MAJOR, _TLS_MINOR);
		ret = TO_ERROR;
	}
	_offset += 2 * sizeof(uint8_t);

#ifdef TO_ENABLE_DTLS
	epoch = _data[_offset++] << 8;
	epoch += _data[_offset++];
	seq += (uint64_t)(_data[_offset++]) << 40;
	seq += (uint64_t)(_data[_offset++]) << 32;
	seq += (uint64_t)(_data[_offset++]) << 24;
	seq += (uint64_t)(_data[_offset++]) << 16;
	seq += (uint64_t)(_data[_offset++]) << 8;
	seq += (uint64_t)(_data[_offset++]);

	/* Verify sequence */
	if (seq < _tls_ctx.sequence_number_down[epoch]) {
		FPRINTF(stderr, "%s: Record sequence already past, not supported, ignoring packet\n",
				__func__);
		return TO_ERROR;
	} else if (seq > _tls_ctx.sequence_number_down[epoch]) {
		FPRINTF(stderr, "%s: Sequence gap (%llu --> %llu), some packets have been lost\n",
				__func__, (long long unsigned int)_tls_ctx.sequence_number_down[epoch],
				(long long unsigned int)seq);
	}
	_tls_ctx.sequence_number_down[epoch] = seq + 1;
#endif

	/* Extract length */
	len = be16toh(*((uint16_t*)(_data + _offset)));
	_offset += sizeof(uint16_t);

	/* Protect buffer overflow */
	if (len + TO_TLS_HEADER_SIZE > _data_size) {
		FPRINTF(stderr, "%s: IO buffer too small, %lu bytes needed\n", __func__,
				(unsigned long int)(len + TO_TLS_HEADER_SIZE));
		return TO_ERROR;
	}

#ifdef TO_ENABLE_DTLS
	/* Store next record in case of several records in the same datagram */
	if (len < total_read_len) {
		_tls_ctx.record_cache_len = total_read_len - len;
		_tls_ctx.record_cache_offs = (_data - _tls_ctx.buf) + TO_TLS_HEADER_SIZE + len;
	}
#endif

	while (total_read_len < len) {

		/* Receive from network */
		if ((_ret = receive_func(_ctx, _data + TO_TLS_HEADER_SIZE + total_read_len,
						len - total_read_len, &read_len, 1000)) != TO_OK) {
			FPRINTF(stderr, "%s: Failed to receive data\n", __func__);
			return TO_ERROR;
		}
		total_read_len += read_len;
	}

	FPRINTF(stdout, "%s: Receive buffer:\n", __func__);
	DUMP_BUFFER(_data, TO_TLS_HEADER_SIZE + len);

	if (ret != TO_OK) {
		return ret;
	}

	if (decryption
	 && *_type != _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC) {
		uint16_t tmp_len;
		int ret = TO_helper_tls_unsecure_message(_data, _data + TO_TLS_HEADER_SIZE,
				_data + TO_TLS_HEADER_SIZE + TO_INITIALVECTOR_SIZE,
				len - TO_INITIALVECTOR_SIZE, _data + TO_TLS_HEADER_SIZE,
				&tmp_len);
		if (ret != TO_OK) {
			FPRINTF(stderr, "%s: Failed to unsecure message\n", __func__);
			return TO_ERROR;
		}
		len = tmp_len;

		/* Rewrite header */
		*((uint16_t*)(_data + _offset - sizeof(uint16_t))) = htobe16(len);

		FPRINTF(stdout, "%s: Decrypted buffer:\n", __func__);
		DUMP_BUFFER(_data, TO_TLS_HEADER_SIZE + len);
	}

cache_check:
	/* TLS handshake records can contains several messages */
	if (*_type == _TLS_RECORD_TYPE_HANDSHAKE) {
		uint32_t tmp_len = 0;

		/* Skip message type */
		++_offset;

		/* 24-bits big-endian length */
		tmp_len += _data[_offset++] << 16;
		tmp_len += _data[_offset++] << 8;
		tmp_len += _data[_offset++];

		/* Check several messages */
		if (tmp_len < len - TO_TLS_HANDSHAKE_HEADER_SIZE) {
			_tls_ctx.cache_len = len - TO_TLS_HANDSHAKE_HEADER_SIZE - tmp_len;
			_tls_ctx.cache_offs = (_data - _tls_ctx.buf) + _offset + tmp_len;
			_tls_ctx.cache_type = _TLS_RECORD_TYPE_HANDSHAKE;
			len -= _tls_ctx.cache_len;
		}
	} else if (*_type == _TLS_RECORD_TYPE_APPLICATION_DATA) {
		if (max_len < len) {
			_tls_ctx.cache_len = len - max_len;
			_tls_ctx.cache_offs = (_data - _tls_ctx.buf) + _offset + max_len;
			_tls_ctx.cache_type = _TLS_RECORD_TYPE_APPLICATION_DATA;
			len -= _tls_ctx.cache_len;
		}
	}

	*_len = len;

	return TO_OK;
}

static int _tls_receive_defrag(_tls_record_type_t *_type, uint8_t **_data, uint32_t *_len,
		uint8_t decryption, void *_ctx, TO_helper_tls_handshake_receive_func receive_func)
{
	int ret;
	uint32_t offset = TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE;
	uint32_t to_read_len = 0;
	uint32_t len;
	int32_t timeout = -1;
#ifdef TO_ENABLE_DTLS
	uint16_t seq;
#endif

	do {
#ifdef TO_ENABLE_DTLS
		uint16_t tmp16 = 0;
		uint32_t tmp32 = 0;
		uint16_t frag_seq;
		uint32_t frag_off;
		uint32_t frag_len;
		uint8_t save[TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE];
		timeout = _tls_ctx.timeout;

		/* Save data which will be overwrote */
		secure_memcpy(save, _tls_ctx.buf + offset - (TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE), TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE);
#endif

		if ((ret = _tls_receive(_type, _tls_ctx.buf + offset - (TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE),
		                        sizeof(_tls_ctx.buf) - (offset - (TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE)),
		                        &len, 0, decryption, timeout, _ctx, receive_func)) != TO_OK) {
#ifdef TO_ENABLE_DTLS
			if (ret == TO_TIMEOUT) {
				/* Double timeout */
				_tls_ctx.timeout *= 2;
				if (_tls_ctx.timeout > _TLS_TIMEOUT_MAX) {
					FPRINTF(stderr, "%s: Timeout reached maximum\n", __func__);
					_tls_ctx.timeout = _TLS_TIMEOUT_MAX;
				}
				FPRINTF(stderr, "%s: New timeout %u\n", __func__, _tls_ctx.timeout);
			}
#endif
			return ret;
		}
#ifdef TO_ENABLE_DTLS
		_tls_ctx.timeout = _TLS_TIMEOUT_MIN;

		if (*_type != _TLS_RECORD_TYPE_HANDSHAKE) {
			break;
		}

		/* Fragment sequence */
		frag_seq = be16toh(*((uint16_t*)(_tls_ctx.buf + offset - 3 * 2 - sizeof(uint16_t))));

		/* Fragment offset */
		secure_memcpy(((uint8_t*)&tmp32) + 1, _tls_ctx.buf + offset - 3 * 2, 3);
		frag_off = be32toh(tmp32);
		tmp32 = 0;

		/* Fragment length */
		secure_memcpy(((uint8_t*)&tmp32) + 1, _tls_ctx.buf + offset + - 3, 3);
		frag_len = be32toh(tmp32);
		tmp32 = 0;

		if (offset > TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE) {

			/* Check fragment sequence */
			if (frag_seq != seq) {
				FPRINTF(stderr, "%s: Bad sequence, retransmission needed\n", __func__);
				/* Return timeout to trigger retransmission */
				return TO_TIMEOUT;
			}

			/* Restore overwrote data */
			secure_memcpy(_tls_ctx.buf + offset - (TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE), save, TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE);

			/* Update TLS record header */
			tmp16 = be16toh(*((uint16_t*)(_tls_ctx.buf + TO_TLS_HEADER_SIZE - sizeof(uint16_t))));
			tmp16 += frag_len;
			*((uint16_t*)(_tls_ctx.buf + TO_TLS_HEADER_SIZE - sizeof(uint16_t))) = htobe16(tmp16);

			/* Update TLS handshake header */
			secure_memcpy(((uint8_t*)&tmp32) + 1, _tls_ctx.buf + TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE - 3, 3);
			tmp32 = be32toh(tmp32);
			tmp32 += frag_len;
			tmp32 = htobe32(tmp32);
			secure_memcpy(_tls_ctx.buf + TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE - 3, ((uint8_t*)&tmp32) + 1, 3);

		} else {
			/* Get total message length */
			tmp32 = 0;
			secure_memcpy(((uint8_t*)&tmp32) + 1, _tls_ctx.buf + TO_TLS_HEADER_SIZE + sizeof(uint8_t), 3);
			to_read_len = be32toh(tmp32);

			/* Set wanted sequence */
			seq = frag_seq;
		}

		/* Move data to right place */
		secure_memmove(_tls_ctx.buf + TO_TLS_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE + frag_off, _tls_ctx.buf + offset, frag_len);

		to_read_len -= frag_len;
		offset += frag_len;
#endif
	} while (to_read_len > 0);

#ifdef TO_ENABLE_DTLS
	*_len = offset - TO_TLS_HEADER_SIZE;
#else
	*_len = len;
#endif
	*_data = _tls_ctx.buf + TO_TLS_HEADER_SIZE;

	return TO_OK;
}

#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
static int _tls_retransmit_last_flight(void *ctx, TO_helper_tls_handshake_send_func send_func)
{
	uint32_t i;
	uint32_t _len;
	int ret;

	FPRINTF(stdout, "Retransmission of last flight start\n");

	/* Resend last flight */
	for (i = 0; i < _tls_ctx.flight_offset; i += TLS_FLIGHT_HEADER_SIZE + _len) {

		/* First bytes is header */
		_tls_flight_header_t *_flight_hdr = (_tls_flight_header_t*)(_tls_ctx.flight_buf + i);

		if (_flight_hdr->type == _TLS_RECORD_TYPE_HANDSHAKE) {
			/* Read header length */
			_len = 0;
			secure_memcpy(((uint8_t*)&_len) + 1, _tls_ctx.flight_buf + i + TLS_FLIGHT_HEADER_SIZE + sizeof(uint8_t), 3);
			_len = TO_TLS_HANDSHAKE_HEADER_SIZE + be32toh(_len);
		} else {
			/* ChangeCipherSpec */
			_len = 1;
		}

		/* Retransmission */
		ret = _tls_send(_flight_hdr->type, _tls_ctx.flight_buf + i, _len,
				_flight_hdr->epoch, _flight_hdr->encryption, ctx, send_func);
		if (ret != TO_OK) {
			FPRINTF(stderr, "%s: Failed to send %u bytes\n", __func__, (uint32_t)_len);
		}
	}

	FPRINTF(stdout, "Last flight retransmitted\n");
	return TO_OK;
}
#endif

int TO_helper_tls_handshake_init(void)
{
	secure_memset(&_tls_ctx, 0, sizeof(_tls_ctx));

	_tls_ctx.state = _STATE_FLIGHT_1;
#if !defined(TO_ENABLE_DTLS) || defined(TO_DISABLE_DTLS_RETRANSMISSION)
	_tls_ctx.flight_buf = _tls_ctx.buf + TO_TLS_HEADER_SIZE;
#endif
#ifdef TO_ENABLE_DTLS
	_tls_ctx.timeout = _TLS_TIMEOUT_MIN;

	if (TO_tls_set_mode(TO_TLS_MODE_DTLS_1_2) != TORSP_SUCCESS) {
#else
	if (TO_tls_set_mode(TO_TLS_MODE_TLS_1_2) != TORSP_SUCCESS) {
#endif
		FPRINTF(stderr, "%s: Failed to set TLS mode\n", __func__);
		return TO_ERROR;
	}

	return TO_OK;
}

int TO_helper_tls_handshake_step(
		void *ctx,
		TO_helper_tls_handshake_send_func send_func,
		TO_helper_tls_handshake_receive_func receive_func)
{

	uint32_t len = 0;
	uint16_t len16;
	int ret = TORSP_INTERNAL_ERROR;
	uint8_t timestamp[TO_TIMESTAMP_SIZE] = { 0x00, 0x00, 0x00, 0x00 };
	_tls_record_type_t type = _TLS_RECORD_TYPE_HANDSHAKE;
	uint8_t next_rx = _tls_ctx.rx;

	if (_tls_ctx.rx) {

		/* Receive mode */
		ret = _tls_receive_defrag(&type, &_tls_ctx.pbuf, &len, _tls_ctx.decryption, ctx, receive_func);
		if (ret != TO_OK) {
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			if (ret == TO_TIMEOUT) {
				/* Retransmit last flight */
				_tls_retransmit_last_flight(ctx, send_func);
			}
			return TO_AGAIN;
#else
			return TO_ERROR;
#endif
		}

		if (type == _TLS_RECORD_TYPE_ALERT) {
			_tls_print_alert((_tls_alert_level_t)*_tls_ctx.pbuf, (_tls_alert_desc_t)*(_tls_ctx.pbuf + 1));
			return TO_ERROR;
		}

#ifdef TO_ENABLE_DTLS
		uint8_t msg_type = _tls_ctx.buf[TO_TLS_HEADER_SIZE];

		/**
		 * Detect replayed flight by checking handshake message type.
		 * Server flight starting by ChangeCipherSpec will not be
		 * retransmitted to query last client flight as it is the last
		 * server flight.
		 */
		if (type == _TLS_RECORD_TYPE_HANDSHAKE && msg_type != (_tls_ctx.state & 0xff)) {
#ifndef TO_DISABLE_DTLS_RETRANSMISSION
			/* Ignore in-flight messages, wait last or missing */
			if (msg_type != _HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST
			 && msg_type != _HANDSHAKE_TYPE_SERVER_HELLO_DONE
			 && msg_type != _HANDSHAKE_TYPE_FINISHED) {
				FPRINTF(stdout, "Ignored in-flight handshake message type %02x\n", msg_type);
			} else {
				/* Retransmit last flight */
				_tls_retransmit_last_flight(ctx, send_func);
			}
#endif

			return TO_AGAIN;
		}
#endif
	} else {
		_tls_ctx.pbuf = _tls_ctx.flight_buf + _tls_ctx.flight_offset;
	}

	if (_tls_ctx.state == _STATE_SERVER_CERTIFICATE_REQUEST
	 && *_tls_ctx.pbuf == _HANDSHAKE_TYPE_SERVER_HELLO_DONE) {
		FPRINTF(stdout, "Client authentication not requested\n");
		_tls_ctx.state = _STATE_SERVER_HELLO_DONE;
	}

	switch (_tls_ctx.state) {
		case _STATE_FLIGHT_1:
			FPRINTF(stdout, "%s: *** Flight 1 ***\n", __func__);
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			_tls_ctx.flight_offset = 0;
			_tls_ctx.pbuf = _tls_ctx.flight_buf;
#endif
			next_rx = 0;
			_tls_ctx.state = _STATE_FLIGHT_1_INIT;
		case _STATE_CLIENT_HELLO:
			ret = TO_tls_get_client_hello(timestamp, _tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) { break; }
			{
				uint8_t *p = _tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE + TO_TLS_HANDSHAKE_HEADER_SIZE + 2 * sizeof(uint8_t) + TO_TLS_RANDOM_SIZE;
				/* Save client session ID */
				_tls_ctx.client_session_id_len = *(p++);
				secure_memcpy(_tls_ctx.client_session_id, p, _tls_ctx.client_session_id_len);
				p += _tls_ctx.client_session_id_len;
			}
			len = (uint32_t)len16;
			FPRINTF(stdout, "%s: ==> ClientHello\n", __func__);
#ifdef TO_ENABLE_DTLS
			_tls_ctx.state = _STATE_FLIGHT_2;
		case _STATE_FLIGHT_2:
			FPRINTF(stdout, "%s: *** Flight 2 ***\n", __func__);
			next_rx = 1;
			_tls_ctx.state = _STATE_FLIGHT_2_INIT;
			break;
		case _STATE_SERVER_HELLO_VERIFY_REQUEST:
			FPRINTF(stdout, "%s: <== HelloVerifyRequest\n", __func__);
			ret = TO_tls_handle_hello_verify_request(_tls_ctx.pbuf, len);
			if (ret != TORSP_SUCCESS) { break; }
			_tls_ctx.state = _STATE_FLIGHT_3;
		case _STATE_FLIGHT_3:
			FPRINTF(stdout, "%s: *** Flight 3 ***\n", __func__);
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			_tls_ctx.flight_offset = 0;
			_tls_ctx.pbuf = _tls_ctx.flight_buf;
#endif
			next_rx = 0;
			_tls_ctx.state = _STATE_FLIGHT_3_INIT;
			break;
		case _STATE_CLIENT_HELLO_WITH_COOKIE:
			ret = TO_tls_get_client_hello(timestamp, _tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) { break; }
			FPRINTF(stdout, "%s: ==> ClientHello (with cookie)\n", __func__);
			len = (uint32_t)len16;
#endif
			_tls_ctx.state = _STATE_FLIGHT_4;
		case _STATE_FLIGHT_4:
			FPRINTF(stdout, "%s: *** Flight 4 ***\n", __func__);
			next_rx = 1;
			_tls_ctx.state = _STATE_FLIGHT_4_INIT;
			break;
		case _STATE_SERVER_HELLO:
			FPRINTF(stdout, "%s: <== ServerHello\n", __func__);
			ret = TO_tls_handle_server_hello(_tls_ctx.pbuf, len);
			if (ret != TORSP_SUCCESS) { break; }
			_tls_ctx.state = _STATE_SERVER_CERTIFICATE;
			{
				uint8_t *p = _tls_ctx.pbuf + TO_TLS_HANDSHAKE_HEADER_SIZE + 2 * sizeof(uint8_t) + TO_TLS_RANDOM_SIZE;
				/* Check session ID */
				uint8_t session_id_len = *(p++);
				if (session_id_len == _tls_ctx.client_session_id_len
				 && !secure_memcmp(_tls_ctx.client_session_id, p, session_id_len)) {
					FPRINTF(stdout, "%s: Session resumption detected\n", __func__);
					_tls_ctx.abbriviated_handshake = 1;
					_tls_ctx.state = _STATE_SERVER_CHANGE_CIPHER_SPEC;
				}
				p += session_id_len;
				_tls_ctx.cipher_suite = (_tls_cipher_suite_t)be16toh(*((uint16_t*)p));
				FPRINTF(stdout, "%s: Detected cipher suite: %04x\n", __func__, _tls_ctx.cipher_suite);
			}
			break;
		case _STATE_SERVER_CERTIFICATE:
			FPRINTF(stdout, "%s: <== Certificate\n", __func__);
			ret = TO_helper_tls_handle_server_certificate(_tls_ctx.pbuf, len);
			if (ret != TO_OK) { break; }
			ret = TORSP_SUCCESS;
			switch (_tls_ctx.cipher_suite) {
				case _TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
					_tls_ctx.state = _STATE_SERVER_KEY_EXCHANGE;
					break;
				case _TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
					_tls_ctx.state = _STATE_SERVER_CERTIFICATE_REQUEST;
					break;
				default:
					FPRINTF(stderr, "%s: No next state defined for cipher suite %04x\n",
							__func__, _tls_ctx.cipher_suite);
					_tls_ctx.state = _STATE_HANDSHAKE_FAILED;
			}
			break;
		case _STATE_SERVER_KEY_EXCHANGE:
			FPRINTF(stdout, "%s: <== ServerKeyExchange\n", __func__);
			ret = TO_tls_handle_server_key_exchange(_tls_ctx.pbuf, len);
			if (ret != TORSP_SUCCESS) { break; }
			_tls_ctx.state = _STATE_SERVER_CERTIFICATE_REQUEST;
			break;
		case _STATE_SERVER_CERTIFICATE_REQUEST:
			FPRINTF(stdout, "%s: <== CertificateRequest\n", __func__);
			ret = TO_tls_handle_certificate_request(_tls_ctx.pbuf, len);
			if (ret != TORSP_SUCCESS) { break; }
			_tls_ctx.state = _STATE_SERVER_HELLO_DONE;
			_tls_ctx.auth_client = 1;
			break;
		case _STATE_SERVER_HELLO_DONE:
			FPRINTF(stdout, "%s: <== ServerHelloDone\n", __func__);
			ret = TO_tls_handle_server_hello_done(_tls_ctx.pbuf);
			if (ret != TORSP_SUCCESS) { break; }
			_tls_ctx.state = _STATE_FLIGHT_5;
		case _STATE_FLIGHT_5:
			FPRINTF(stdout, "%s: *** Flight 5 ***\n", __func__);
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
			_tls_ctx.flight_offset = 0;
			_tls_ctx.pbuf = _tls_ctx.flight_buf;
#endif
			next_rx = 0;
			if (_tls_ctx.auth_client) {
				_tls_ctx.state = _STATE_FLIGHT_5_INIT;
			} else {
				_tls_ctx.state = _STATE_FLIGHT_5_INIT_NO_CLIENT_AUTH;
			}
			break;
		case _STATE_CLIENT_CERTIFICATE:
			ret = TO_helper_tls_get_certificate(_tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TO_OK) {
				/* Try to fallback on old method */
				ret = TO_tls_get_certificate(_tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
				if (ret != TORSP_SUCCESS) { break; }
			}
			FPRINTF(stdout, "%s: ==> Certificate\n", __func__);
			len = (uint32_t)len16;
			_tls_ctx.state = _STATE_CLIENT_KEY_EXCHANGE;
			ret = TORSP_SUCCESS;
			break;
		case _STATE_CLIENT_KEY_EXCHANGE:
			ret = TO_tls_get_client_key_exchange(_tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) { break; }
			FPRINTF(stdout, "%s: ==> ClientKeyExchange\n", __func__);
			len = (uint32_t)len16;
			switch (_tls_ctx.cipher_suite) {
				case _TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
					if (_tls_ctx.auth_client) {
						_tls_ctx.state = _STATE_CLIENT_CERTIFICATE_VERIFY;
					} else {
						_tls_ctx.state = _STATE_CLIENT_CHANGE_CIPHER_SPEC;
					}
					break;
				case _TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
					_tls_ctx.state = _STATE_CLIENT_CHANGE_CIPHER_SPEC;
					break;
				default:
					FPRINTF(stderr, "%s: No next state defined for cipher suite %04x\n",
							__func__, _tls_ctx.cipher_suite);
					_tls_ctx.state = _STATE_HANDSHAKE_FAILED;
			}
			break;
		case _STATE_CLIENT_CERTIFICATE_VERIFY:
			ret = TO_tls_get_certificate_verify(_tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE, &len16);
			if (ret != TORSP_SUCCESS) { break; }
			FPRINTF(stdout, "%s: ==> CertificateVerify\n", __func__);
			len = (uint32_t)len16;
			_tls_ctx.state = _STATE_CLIENT_CHANGE_CIPHER_SPEC;
			break;
		case _STATE_CLIENT_CHANGE_CIPHER_SPEC:
			ret = TO_tls_get_change_cipher_spec(_tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE);
			if (ret != TORSP_SUCCESS) { break; }
			FPRINTF(stdout, "%s: ==> ChangeCipherSpec\n", __func__);
			type = _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC;
			len = TO_TLS_CHANGE_CIPHER_SPEC_SIZE;
			_tls_ctx.state = _STATE_CLIENT_FINISHED;
			break;
		case _STATE_CLIENT_FINISHED:
			_tls_ctx.encryption = 1;
#ifdef TO_ENABLE_DTLS
			++_tls_ctx.epoch;
#endif
			ret = TO_tls_get_finished(_tls_ctx.pbuf + TLS_FLIGHT_HEADER_SIZE);
			if (ret != TORSP_SUCCESS) { break; }
			FPRINTF(stdout, "%s: ==> Finished\n", __func__);
			len = TO_TLS_FINISHED_PAYLOAD_SIZE;
			if (_tls_ctx.abbriviated_handshake) {
				_tls_ctx.state = _STATE_HANDSHAKE_DONE;
				break;
			} else {
				_tls_ctx.state = _STATE_FLIGHT_6;
			}
		case _STATE_FLIGHT_6:
			FPRINTF(stdout, "%s: *** Flight 6 ***\n", __func__);
			next_rx = 1;
			_tls_ctx.state = _STATE_FLIGHT_6_INIT;
			break;
		case _STATE_SERVER_CHANGE_CIPHER_SPEC:
			FPRINTF(stdout, "%s: <== ChangeCipherSpec\n", __func__);
			ret = TO_tls_handle_change_cipher_spec(_tls_ctx.pbuf);
			if (ret != TORSP_SUCCESS) { break; }
			_tls_ctx.decryption = 1;
			_tls_ctx.state = _STATE_SERVER_FINISHED;
			break;
		case _STATE_SERVER_FINISHED:
			FPRINTF(stdout, "%s: <== Finished\n", __func__);
			ret = TO_tls_handle_finished(_tls_ctx.pbuf);
			if (ret != TORSP_SUCCESS) { break; }
			if (_tls_ctx.abbriviated_handshake) {
				_tls_ctx.state = _STATE_CLIENT_CHANGE_CIPHER_SPEC;
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
				_tls_ctx.flight_offset = 0;
				_tls_ctx.pbuf = _tls_ctx.flight_buf;
#endif
				next_rx = 0;
			} else {
				_tls_ctx.state = _STATE_HANDSHAKE_DONE;
			}
			break;
		default:
			FPRINTF(stderr, "Unknown state %u\n", _tls_ctx.state);
			break;
	}

	if (ret != TORSP_SUCCESS) {
		FPRINTF(stderr, "%s: TO call failed\n", __func__);
		_tls_send_alert(_ALERT_LEVEL_FATAL, _ALERT_DESC_CLOSE_NOTIFY, ctx, send_func);
		return TO_ERROR;
	}

	if (!_tls_ctx.rx) {

		/* Handle buffer overflow */
		if (_tls_ctx.pbuf + len > _tls_ctx.flight_buf + TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE) {
			FPRINTF(stderr, "%s: flight buffer overflow, %lu bytes needed\n", __func__,
					(unsigned long int)((_tls_ctx.pbuf - _tls_ctx.flight_buf) + len));
			return TO_ERROR;
		}

		ret = _tls_send(type, _tls_ctx.pbuf, len,
#ifdef TO_ENABLE_DTLS
				_tls_ctx.epoch,
#endif
				_tls_ctx.encryption, ctx, send_func);
		if (ret != TO_OK) {
			FPRINTF(stderr, "%s: Failed to send %u bytes\n", __func__, (uint32_t)len);
			return TO_ERROR;
		}
#if defined(TO_ENABLE_DTLS) && !defined(TO_DISABLE_DTLS_RETRANSMISSION)
		_tls_ctx.flight_offset += TLS_FLIGHT_HEADER_SIZE + len;
#endif
	}

	_tls_ctx.rx = next_rx;

	if (_tls_ctx.state != _STATE_HANDSHAKE_DONE) {
		return TO_AGAIN;
	}

	return TO_OK;
}

int TO_helper_tls_handshake(
		void *ctx,
		TO_helper_tls_handshake_send_func send_func,
		TO_helper_tls_handshake_receive_func receive_func)
{
	int ret;

	if ((ret = TO_helper_tls_handshake_init()) != TO_OK) {
		FPRINTF(stderr, "%s: TO_helper_tls_handshake_init() failed\n", __func__);
		return ret;
	}

	while ((ret = TO_helper_tls_handshake_step(ctx, send_func, receive_func)) == TO_AGAIN);

	if (ret != TO_OK) {
		FPRINTF(stderr, "%s: TO_helper_tls_handshake_step() failed\n", __func__);
		return ret;
	}

	return ret;
}

int TO_helper_tls_send_message(
		uint8_t *msg, uint32_t msg_len,
		void *ctx, TO_helper_tls_handshake_send_func send_func)
{
	int ret;
	if (msg_len > TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE - TLS_FLIGHT_HEADER_SIZE
	 || msg_len > TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE - TO_TLS_HEADER_SIZE) {
		FPRINTF(stderr, "%s: IO buffer too small to send %u bytes\n", __func__, msg_len);
		return TO_ERROR;
	}
	secure_memcpy(_tls_ctx.flight_buf + TLS_FLIGHT_HEADER_SIZE, msg, msg_len);
	if ((ret = _tls_send(_TLS_RECORD_TYPE_APPLICATION_DATA, _tls_ctx.flight_buf,
					msg_len,
#ifdef TO_ENABLE_DTLS
					_tls_ctx.epoch,
#endif
					1, ctx, send_func)) != TO_OK) {
		return ret;
	}
	return TO_OK;
}

int TO_helper_tls_receive_message(
		uint8_t *msg, uint32_t max_msg_len, uint32_t *msg_len,
		void *ctx, TO_helper_tls_handshake_receive_func receive_func)
{
	return TO_helper_tls_receive_message_with_timeout(msg, max_msg_len, msg_len, -1, ctx, receive_func);
}

int TO_helper_tls_receive_message_with_timeout(
		uint8_t *msg, uint32_t max_msg_len, uint32_t *msg_len, int32_t timeout,
		void *ctx, TO_helper_tls_handshake_receive_func receive_func)
{
	int ret;
	_tls_record_type_t _type = _TLS_RECORD_TYPE_APPLICATION_DATA;
	do {
		if ((ret = _tls_receive(&_type, _tls_ctx.buf, TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE, msg_len, max_msg_len, 1, timeout, ctx, receive_func)) != TO_OK) {
			return ret;
		}
		if (max_msg_len < *msg_len) {
			FPRINTF(stderr, "%s: Message too long for given buffer (%u > %u)\n", __func__, max_msg_len, *msg_len);
			return TO_ERROR;
		}
		if (_type != _TLS_RECORD_TYPE_APPLICATION_DATA) {
			if (_type == _TLS_RECORD_TYPE_ALERT) {
				uint8_t *p = _tls_ctx.buf + TO_TLS_HEADER_SIZE;
				_tls_print_alert((_tls_alert_level_t)*p, (_tls_alert_desc_t)*(p + 1));
			} else {
				FPRINTF(stderr, "%s: Bad record type %02x, %02x expected\n", __func__,
						_type, _TLS_RECORD_TYPE_APPLICATION_DATA);
			}
		}
	} while (_type != _TLS_RECORD_TYPE_APPLICATION_DATA);
	secure_memcpy(msg, _tls_ctx.buf + TO_TLS_HEADER_SIZE, *msg_len);
	return TO_OK;
}

#endif // TO_DISABLE_TLS_HELPER
