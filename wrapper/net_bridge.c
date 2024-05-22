/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2017 Trusted Objects
 */

/**
 * @file net_bridge.c
 * @brief Network wrapper, writing to and reading from a network I2C bridge.
 *
 * The protocol is detailed below.
 *
 * Protocol version: 1.1
 *
 * Warning: Status codes used by the protocol below are libTO status codes
 * shifted 8-bits to the right.
 *
 * == Hello request ==
 * Hello request is used to notify bridge about its protocol version.
 *       ----------------------------------------------------------
 * Send: |  0x00 (hello)  |  Version (major)  |  Version (minor)  |
 *       ----------------------------------------------------------
 *           \ 1 byte /         \ 1 byte /          \ 1 byte /
 * protocol major version number is incremented on API change breaking backward
 * compatibility, minor version number is incremented on every other protocol
 * revision and reset to 0 on major version number increment.
 *
 * == Config request ==
 * Used to configure remote bridge I2C bus.
 *       -----------------------------------------------------
 * Send: |  0x01 (config)  |  I2C address  |  Misc. settings |
 *       -----------------------------------------------------
 *           \ 1 byte /     \ 1 byte /         \ 1 byte /
 * I2C address setting is 7 bits address (MSB=0)
 * Misc settings byte is represented as follows, from MSB to LSB:
 *  | RES | RES | RES | RES | RES | RES | RES | last byte NACKed |
 *   - last byte NACKed: the I2C device NACK last written byte
 *       ----------------------------
 * Recv: |  Status (TO_OK=success)  |
 *       ----------------------------
 * the status informs if the configuration has correctly been applied by remote
 * I2C bridge.
*
 * == Write request ==
 * Used to send to the bridge data to be written to I2C device.
 *       -------------------------------------- - - - - - - - - - - - - - - ----
 * Send: |  0x02 (write)  |  Data length  |                 Data               |
 *       -------------------------------------- - - - - - - - - - - - - - - ----
 *           \ 1 byte /      \ 2 bytes /           \ Data length bytes /
 *       ----------------------------
 * Recv: |  Status (TO_OK=success)  |
 *       ----------------------------
 * the status stands for I2C bridge data write on I2C, and is set to TO_OK
 * if the bridge succeed to write.
 *
 * == Read request ==
 * Used to read from the bridge data read from I2C device.
 *       ---------------------------------
 * Send: |  0x03 (read)  |  Data length  |
 *       ---------------------------------
 *          \ 1 byte /      \ 2 bytes /
 *       ----------------------------
 * Recv: |  Status (TO_OK=success)  |
 *       ----------------------------
 * the status stands for I2C bridge data read on I2C, and is set to TO_OK if
 * the bridge succeed to read.
 * The following operation is to be made only if status value is TO_OK, to
 * get the data read from I2C device by the bridge.
 *       ----- - - - - - - - - - - - - - - ----
 * Recv: |                 Data               |
 *       ----- - - - - - - - - - - - - - - ----
 *                \ Data length bytes /
 *
 * == Last command duration request ==
 * Used to get last command duration from the bridge I2C wrapper.
 *       ---------------------------------
 * Send: |  0x04 (last command duration)  |
 *       ---------------------------------
 *                  \ 1 byte /
 *       ----------------------------
 * Recv: |  Status (TO_OK=success)  |
 *       ----------------------------
 * the status stands for I2C bridge last command duration on I2C, and is set to
 * TO_OK if the bridge succeed to get last command duration.
 * The following operation is to be made only if status value is TO_OK, to
 * get the last command duration from I2C wrapper by the bridge.
 *       -------------------------------------------------------
 * Recv: | Last command duration in micro-seconds (big-endian) |
 *       -------------------------------------------------------
 *                           \ 4 bytes /
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <winsock2.h>

#elif defined (linux)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/tcp.h>
#define closesocket(s) close(s)
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef struct in_addr IN_ADDR;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1

#else
#error Platform not supported by network I2C wrapper
#endif

#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include <errno.h>
#endif

#include <TO_i2c_wrapper.h>
#include <TO_endian.h>

#ifdef WIN32
#define BRIDGE_HOSTNAME_FILEPATH \
	"c:/msys32/etc/trusted-objects/i2c-net-bridge-hostname"
#define CERT_FILEPATH \
	"c:/msys32/etc/trusted-objects/i2c-net-bridge.pem"
#define CA_CERT_FILEPATH \
	"c:/msys32/etc/trusted-objects/rootca.pem"
#define PKEY_FILEPATH \
	"c:/msys32/etc/trusted-objects/i2c-net-bridge.key"
#elif defined (linux)
#define BRIDGE_HOSTNAME_FILEPATH "/etc/trusted-objects/i2c-net-bridge-hostname"
#define CERT_FILEPATH "/etc/trusted-objects/i2c-net-bridge.pem"
#define CA_CERT_FILEPATH "/etc/trusted-objects/rootca.pem"
#define PKEY_FILEPATH "/etc/trusted-objects/i2c-net-bridge.key"
#endif
#define BRIDGE_HOSTNAME_ENV "I2C_NET_BRIDGE_HOSTNAME"
#define BRIDGE_HOSTNAME_MAXSIZE 256
#define BRIDGE_PORT "42424"
#define BRIDGE_PORT_ENV "I2C_NET_BRIDGE_PORT"
#define BRIDGE_PORT_MAXSIZE 6

#define REQ_HELLO 0x00
#define REQ_CONFIG 0x01
#define REQ_WRITE 0x02
#define REQ_READ 0x03
#define REQ_LCD 0x04

const unsigned char default_protocol_version[] = {1, 1};
#define DEFAULT_I2C_ADDR 0x50
#define DEFAULT_MISC_SETTINGS TO_CONFIG_NACK_LAST_BYTE

#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
static mbedtls_ssl_context tls;
static mbedtls_net_context tls_server_fd = {.fd = INVALID_SOCKET};
static mbedtls_entropy_context tls_entropy;
static mbedtls_ctr_drbg_context tls_ctr_drbg;
static mbedtls_ssl_config tls_conf;
static mbedtls_x509_crt tls_clicert;
static mbedtls_pk_context tls_pkey;
#else
static SOCKET sock = INVALID_SOCKET;
#endif
static unsigned char i2c_config[] = {DEFAULT_I2C_ADDR, DEFAULT_MISC_SETTINGS};

#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
static void tls_log_cb(void *ctx, int level, const char *file, int line,
		const char *str)
{
	(void)level;
	(void)file;
	(void)line;
	fprintf((FILE *)ctx, "TLS: %s", str);
}

static void log_tls_err(const char* message, int code)
{
	char error_details[100];
	mbedtls_strerror(code, error_details, sizeof(error_details));
	fprintf(stderr, "%s: %s\n", message, error_details);
}

static void log_tls_verify_info(int code)
{
	char details[512];
	if (code == 0)
		return;
	mbedtls_x509_crt_verify_info(details, sizeof(details), "", code);
	fprintf(stderr, "Verification info: %s\n", details);
}
#endif

/**
 * send_bridge() - Send data to I2C bridge
 * @data: Data to send
 * @length: Data length to send
 *
 * Return: number of bytes send, or -1 on error (then errno is set)
 */
static int send_bridge(const void *data, uint32_t length)
{
#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
	int ret, orig_length;
	orig_length = length;
	while ((ret = mbedtls_ssl_write(&tls, data, length)) < (int)length) {
		if (ret < 0) {
		       if (ret != MBEDTLS_ERR_SSL_WANT_READ
				&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				log_tls_err("TLS write error", ret);
				errno = EIO;
				return -1;
		       }
		} else {
			data += ret;
			length -= ret;
		}
	}
	return orig_length;
#else
	return send(sock, data, length, 0);
#endif
}

/**
 * recv_bridge() - Receive data from I2C bridge
 * @data: Data buffer for reception
 * @length: Data length to receive
 *
 * Return: number of bytes received, or -1 on error (then errno is set)
 */
static int recv_bridge(void *data, uint32_t length)
{
#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
	int ret, orig_length;
	orig_length = length;
	while ((ret = mbedtls_ssl_read(&tls, data, length)) < (int)length) {
		if (ret == MBEDTLS_ERR_SSL_WANT_READ
				|| ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			log_tls_err("TLS closed by peer", ret);
			errno = ECONNRESET;
			return -1;
		}
		if (ret < 0) {
			log_tls_err("TLS read error", ret);
			errno = EIO;
			return -1;
		}
		if (ret == 0) {
			fprintf(stderr, "TLS read EOF\n");
			errno = EIO;
			return -1;
		}
		data += ret;
		length -= ret;
	}
	return orig_length;
#else
	return recv(sock, data, length, 0);
#endif
}

static int send_hello(void)
{
	const unsigned char req = REQ_HELLO;

	/* Send hello request header */
	if (send_bridge(&req, sizeof(req)) < 0) {
		perror("I2C network bridge wrapper hello error: hello request");
		return TO_ERROR;
	}
	/* Send version */
	if (send_bridge(default_protocol_version,
				sizeof(default_protocol_version)) < 0) {
		perror("I2C network bridge wrapper hello error: "
				"unable to send version");
		return TO_ERROR;
	}

	return TO_OK;
}

/**
 * data_config() - Configure bridge I2C bus
 *
 * The following sequence is necessary to configure bridge I2C bus (in
 * case of error at any step, the sequence is aborted):
 * 1) send config request header (0x00)
 * 1) Send config (2 bytes)
 *  => remote I2C bridge configures its I2C bus
 * 3) Read and check status (1 byte)
 *  => remote I2C bridge returns I2C bus configuration status
 *
 * Return TO_OK if the sequence was sucessfully completed
 */
static int data_config(void)
{
	const unsigned char req = REQ_CONFIG;
	char short_st;
	uint16_t status;

	/* Send configuration request header */
	if (send_bridge(&req, sizeof(req)) < 0) {
		perror("I2C network bridge wrapper config error: "
				"config request");
		return TO_ERROR;
	}
	/* Send configuration */
	if (send_bridge(i2c_config, sizeof(i2c_config)) < 0) {
		perror("I2C network bridge wrapper config error: "
				"unable to send configuration");
		return TO_ERROR;
	}
	/* Read remote I2C configuration status */
	if (recv_bridge(&short_st, 1) < 0) {
		perror("I2C network bridge wrapper config error: get status");
		return TO_ERROR;
	}
	/* Convert status to a libTO status code and check it */
	status = short_st << 8;
	if (status != TO_OK) {
		fprintf(stderr, "I2C network bridge wrapper config error: "
				"status %04X\n", status);
		return TO_ERROR;
	}

	return TO_OK;
}

/**
 * TO_data_init() - Initializes TCP/IP connection to remote I2C bridge
 */
int TO_data_init(void)
{
	char *p;
	char hostname[BRIDGE_HOSTNAME_MAXSIZE + 1] = "";
	char port[BRIDGE_PORT_MAXSIZE + 1];
	FILE *hostname_file;
	uint32_t size;
	int ret, retval = TO_ERROR, enable = 1;
#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
	const unsigned char perso[] = "libTO_i2c_net_bridge";
	SOCKET sock;
#else
	struct hostent *hostinfo = NULL;
	SOCKADDR_IN sockaddr_dst = {0};
#ifdef WIN32
	WSADATA wsa;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) < 0) {
		fprintf(stderr, "I2C network wrapper WSAStartup failed\n");
		goto error;
	}
#endif
#endif

#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
	mbedtls_net_init(&tls_server_fd);
	mbedtls_ssl_init(&tls);
	mbedtls_ssl_config_init(&tls_conf);
	mbedtls_x509_crt_init(&tls_clicert);
	mbedtls_pk_init(&tls_pkey);
	mbedtls_ctr_drbg_init(&tls_ctr_drbg);
	mbedtls_entropy_init(&tls_entropy);
	ret = mbedtls_ctr_drbg_seed(&tls_ctr_drbg,
			mbedtls_entropy_func, &tls_entropy,
			perso, sizeof(perso));
	if (ret != 0) {
		log_tls_err("Error on entropy init", ret);
		goto error;
	}
	ret = mbedtls_x509_crt_parse_file(&tls_clicert, CERT_FILEPATH);
	if(ret < 0) {
		log_tls_err("Error while loading cert", ret);
		goto error;
	}
	ret = mbedtls_x509_crt_parse_file(&tls_clicert, CA_CERT_FILEPATH);
	if(ret < 0) {
		log_tls_err("Error while loading CA cert", ret);
		goto error;
	}
	ret = mbedtls_pk_parse_keyfile(&tls_pkey, PKEY_FILEPATH, NULL);
	if(ret < 0) {
		log_tls_err("Error while loading pkey", ret);
		goto error;
	}
#endif

	hostname_file = fopen(BRIDGE_HOSTNAME_FILEPATH, "r");
	if (hostname_file != NULL) {
		size = fread(hostname, sizeof(char), BRIDGE_HOSTNAME_MAXSIZE,
					hostname_file);
		fclose(hostname_file);
		hostname[size - 1] = '\0';
	}

	if ((p = strchr(hostname, ':')) != NULL) {
		*p = '\0';
		strncpy(port, p + 1, BRIDGE_PORT_MAXSIZE);
	} else {
		strcpy(port, BRIDGE_PORT);
	}

	/* Try to load hostname from environment variable */
	if ((p = getenv(BRIDGE_HOSTNAME_ENV)) != NULL) {
		strncpy(hostname, p, BRIDGE_HOSTNAME_MAXSIZE);
	}

	/* Try to load port from environment variable */
	if ((p = getenv(BRIDGE_PORT_ENV)) != NULL) {
		strncpy(port, p, BRIDGE_PORT_MAXSIZE);
	}

	if (strlen(hostname) == 0) {
		fprintf(stderr, "Can not open %s and no environment variable set\n",
				BRIDGE_HOSTNAME_FILEPATH);
		goto error;
	}

#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
	ret = mbedtls_net_connect(&tls_server_fd, hostname, port,
			MBEDTLS_NET_PROTO_TCP);
	if (ret != 0) {
		log_tls_err("Unable to connect", ret);
		goto error;
	}
	sock = tls_server_fd.fd;
	ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		log_tls_err("Failed to init TLS config", ret);
		goto error;
	}
	mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&tls_conf, tls_clicert.next, NULL);
	ret = mbedtls_ssl_conf_own_cert(&tls_conf, &tls_clicert, &tls_pkey);
	if (ret != 0) {
		log_tls_err("Failed to configure cert", ret);
		goto error;
	}
	mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &tls_ctr_drbg);
	mbedtls_ssl_conf_dbg(&tls_conf, tls_log_cb, stdout);
	ret = mbedtls_ssl_setup(&tls, &tls_conf);
	if (ret != 0) {
		log_tls_err("Failed to configure TLS", ret);
		goto error;
	}
	mbedtls_ssl_set_bio(&tls, &tls_server_fd,
			mbedtls_net_send, mbedtls_net_recv, NULL);
	while ((ret = mbedtls_ssl_handshake(&tls)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ
				&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			log_tls_err("TLS handhake error", ret);
			ret = mbedtls_ssl_get_verify_result(&tls);
			log_tls_verify_info(ret);
			goto error;
		}
	}
#else
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		perror("I2C network bridge wrapper: socket creation error");
		goto error;
	}
	hostinfo = gethostbyname(hostname);
	if (hostinfo == NULL) {
		fprintf(stderr, "I2C network bridge wrapper: unknown host %s\n",
				hostname);
		goto error;
	}
	sockaddr_dst.sin_family = AF_INET;
	sockaddr_dst.sin_addr = *(IN_ADDR *) hostinfo->h_addr;
	sockaddr_dst.sin_port = htons(atoi(port));
	if (connect(sock, (SOCKADDR *)&sockaddr_dst, sizeof(SOCKADDR))
			== SOCKET_ERROR) {
		perror("I2C network bridge wrapper: connect error");
		goto error;
	}
#endif
	ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
			(void *)&enable, sizeof(enable));
	if (ret != 0) {
		perror("Unable to set socket options");
		goto error;
	}

	if (send_hello() != TO_OK)
		goto error;
	if (data_config() != TO_OK)
		goto error;

	retval = TO_OK;
goto end;
error:
	TO_data_fini();
end:
	return retval;
}

/**
 * TO_data_fini() - Finish connection with remote I2C bridge
 */
int TO_data_fini(void)
{
#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
	mbedtls_ssl_close_notify(&tls);
	mbedtls_net_free(&tls_server_fd);
	tls_server_fd.fd = INVALID_SOCKET;
	mbedtls_x509_crt_free(&tls_clicert);
	mbedtls_pk_free(&tls_pkey);
	mbedtls_ssl_free(&tls);
	mbedtls_ssl_config_free(&tls_conf);
	mbedtls_ctr_drbg_free(&tls_ctr_drbg);
	mbedtls_entropy_free(&tls_entropy);
#else
	if (sock != INVALID_SOCKET) {
		closesocket(sock);
		sock = INVALID_SOCKET;
	}
#ifdef WIN32
	WSACleanup();
#endif
#endif
	return TO_OK;
}

#ifdef TO_I2C_WRAPPER_CONFIG
int TO_data_config(const TO_i2c_config_t *config)
{
#ifdef TO_ENABLE_I2C_NET_BRIDGE_TLS
	int sock = tls_server_fd.fd;
#endif
	i2c_config[0] = config->i2c_addr;
	i2c_config[1] = config->misc_settings;
	if (sock != INVALID_SOCKET) {
		if (data_config() != TO_OK)
			return TO_ERROR;
	}
	return TO_OK;
}
#endif

/**
 * TO_data_read() - Read data from remote I2C bridge.
 *
 * The following sequence is necessary to read data from remote I2C bridge (in
 * case of error at any step, the sequence is aborted):
 * 1) send read request header (0x02)
 * 2) send expected data size (2 bytes)
 *  => remote I2C bridge tries to read this amount of data from I2C device
 * 3) read and check status (1 byte)
 *  => remote I2C bridge returns I2C read status
 * 4) Read response data
 *  => remote I2C bridge returns data previously read from I2C device
 *
 * Return TO_OK if the sequence was sucessfully completed
 */
int TO_data_read(void *data, unsigned int length)
{
	const unsigned char req = REQ_READ;
	uint16_t data_len;
	char short_st;
	uint16_t status;

	/* Send read request header */
	if (send_bridge(&req, sizeof(req)) < 0) {
		perror("I2C network bridge wrapper read error: read request");
		return TO_ERROR;
	}
	/* Send expected data size */
	data_len = htons((uint16_t) length);
	if (send_bridge(&data_len, sizeof(data_len)) < 0) {
		perror("I2C network bridge wrapper read error: send data size");
		return TO_ERROR;
	}
	/* Read remote I2C read status */
	if (recv_bridge(&short_st, 1) < 0) {
		perror("I2C network bridge wrapper read error: get status");
		return TO_ERROR;
	}
	/* Convert status to a libTO status code and check it */
	status = short_st << 8;
	if (status != TO_OK) {
		fprintf(stderr, "I2C network bridge wrapper read error: "
				"status %04X\n", status);
		return TO_ERROR;
	}
	/* Read response data */
	if (recv_bridge(data, length) < 0)
	{
		perror("I2C network bridge wrapper read error");
		return TO_ERROR;
	}

	return TO_OK;
}

/**
 * TO_data_write() - Write data to remote I2C bridge
 *
 * The following sequence is necessary to write data to remote I2C bridge (in
 * case of error at any step, the sequence is aborted):
 * 1) send write request header (0x01)
 * 1) Send data size (2 bytes)
 * 2) Send data
 *  => remote I2C bridge writes data to I2C device
 * 3) Read and check status (1 byte)
 *  => remote I2C bridge returns I2C write status
 *
 * Return TO_OK if the sequence was sucessfully completed
 */
int TO_data_write(const void *data, unsigned int length)
{
	const unsigned char req = REQ_WRITE;
	uint16_t data_len;
	char short_st;
	uint16_t status;

	/* Send write request header */
	if (send_bridge(&req, sizeof(req)) < 0) {
		perror("I2C network bridge wrapper write error: write request");
		return TO_ERROR;
	}
	/* Send data size */
	data_len = htons((uint16_t) length);
	if (send_bridge(&data_len, sizeof(data_len)) < 0) {
		perror("I2C network bridge wrapper write error: "
				"unable to send data size");
		return TO_ERROR;
	}
	/* Send data */
	if (send_bridge(data, length) < 0) {
		perror("I2C network bridge wrapper write error: write data");
		return TO_ERROR;
	}
	/* Read remote I2C write status */
	if (recv_bridge(&short_st, 1) < 0) {
		perror("I2C network bridge wrapper write error: get status");
		return TO_ERROR;
	}
	/* Convert status to a libTO status code and check it */
	status = short_st << 8;
	if (status != TO_OK) {
		fprintf(stderr, "I2C network bridge wrapper write error: "
				"status %04X\n", status);
		return TO_ERROR;
	}

	return TO_OK;
}

/**
 * TO_data_last_command_duration() - Get last command duration of remote I2C
 * bridge
 *
 * The following sequence is necessary to get last command duration from remote
 * I2C bridge (in  * case of error at any step, the sequence is aborted):
 * 1) send last command duration request header (0x04)
 * 2) read and check status (1 byte)
 *  => remote I2C bridge returns I2C last command duration status
 * 4) Read response duration
 *  => remote I2C bridge returns last command duration
 *
 * Return TO_OK if the sequence was sucessfully completed
 */
int TO_data_last_command_duration(unsigned int *duration)
{
	const unsigned char req = REQ_LCD;
	char short_st;
	uint16_t status;
	uint32_t tmp;

	/* Send last command duration request header */
	if (send_bridge(&req, sizeof(req)) < 0) {
		perror("I2C network bridge wrapper last command duration error: "
			   "read request");
		return TO_ERROR;
	}
	/* Read remote I2C last command duration status */
	if (recv_bridge(&short_st, 1) < 0) {
		perror("I2C network bridge wrapper last command duration error: "
			   "get status");
		return TO_ERROR;
	}
	/* Convert status to a libTO status code and check it */
	status = short_st << 8;
	if (status != TO_OK) {
		fprintf(stderr, "I2C network bridge wrapper last command duration "
				"error: status %04X\n", status);
		return TO_ERROR;
	}
	/* Read response duration */
	if (recv_bridge((uint8_t*)&tmp, sizeof(uint32_t)) < 0)
	{
		perror("I2C network bridge wrapper last command duration error");
		return TO_ERROR;
	}

	*duration = be32toh(tmp);

	return TO_OK;
}
