#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>

#include <libTO_config.h>
#include <TO.h>
#include <TO_helper.h>

#ifndef TO_DISABLE_TLS_HELPER

typedef struct {
	int sock;
	struct sockaddr_in si_other;
} _ctx_t;

int send_func(void *ctx, const uint8_t *data, const uint32_t len)
{
	_ctx_t *_ctx = (_ctx_t*)ctx;
#if defined(TO_ENABLE_DTLS)
	int32_t _len = sendto(_ctx->sock, data, len, 0, (struct sockaddr *)&_ctx->si_other, sizeof(_ctx->si_other));
#else
	int32_t _len = send(_ctx->sock, data, len, 0);
#endif
	if (_len == -1) {
		perror("sendto");
		exit(1);
	}

	return TO_OK;
}

int receive_func(void *ctx, uint8_t *data, const uint32_t len, uint32_t *read_len, int32_t timeout)
{
	_ctx_t *_ctx = (_ctx_t*)ctx;
	int32_t _len;
	struct pollfd fd = { .fd = _ctx->sock, .events = POLLIN };
	int ret;

	if ((ret = poll(&fd, 1, timeout)) < 0) {
		return TO_ERROR;
	}
	if (!ret) {
		return TO_TIMEOUT;
	}

#if defined(TO_ENABLE_DTLS)
	socklen_t __len = sizeof(struct sockaddr);
	_len = recvfrom(_ctx->sock, data, len, 0, (struct sockaddr *)&_ctx->si_other, &__len);
#else
	_len = recv(_ctx->sock, data, len, 0);
#endif
	if (_len == -1) {
		perror("recvfrom");
		exit(1);
	}
	*read_len = _len;
	return TO_OK;
}

int main(int argc, const char *argv[])
{
	_ctx_t _ctx;
	int ret;
	uint8_t data[512];
	int32_t len;
	struct hostent *host;

	if (argc != 3) {
		fprintf(stderr, "Usage:\n\t%s <server ip/hostname> <server port>\n", argv[0]);
		exit(1);
	}

#if defined(TO_ENABLE_DTLS)
	if ((_ctx.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
#else
	if ((_ctx.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
#endif
		perror("socket");
		exit(1);
	}

	memset((char *) &_ctx.si_other, 0, sizeof(_ctx.si_other));
	_ctx.si_other.sin_family = AF_INET;
	_ctx.si_other.sin_port = htons(atoi(argv[2]));

	if ((host = gethostbyname(argv[1])) == NULL) {
		fprintf(stderr, "gethostbyname() failed\n");
		exit(1);
	}

#if !defined(TO_ENABLE_DTLS)
	uint16_t i;
	for (i = 0; host->h_addr_list[i] != NULL; ++i) {
		memcpy(&_ctx.si_other.sin_addr, host->h_addr_list[0], host->h_length);

		if ((ret = connect(_ctx.sock, (struct sockaddr *)&_ctx.si_other, sizeof(struct sockaddr))) < 0) {
			perror("connect");
			continue;
		}

		break;
	}

	if (ret < 0) {
		exit(1);
	}
#endif

	if ((ret = TO_init()) != TO_OK) {
		fprintf(stderr, "TO_init failed\n");
		exit(1);
	}

	if ((ret = TO_helper_tls_handshake((void*)&_ctx, send_func, receive_func)) != TO_OK) {
		fprintf(stderr, "TO_helper_tls_handshake failed\n");
		exit(1);
	}

	fprintf(stdout, "Handshake done\n");
	fflush(stdout);

	while ((len = read(STDIN_FILENO, data, sizeof(data))) > 0) {

		uint32_t _len;

		if ((ret = TO_helper_tls_send_message(data, len, (void*)&_ctx, send_func)) != TO_OK) {
			fprintf(stderr, "TO_helper_tls_send_message failed\n");
			exit(1);
		}

		if ((ret = TO_helper_tls_receive_message(data, sizeof(data), &_len, (void*)&_ctx, receive_func)) != TO_OK) {
			fprintf(stderr, "TO_helper_tls_receive_message failed\n");
			exit(1);
		}

		fprintf(stdout, "Message from server:\n");
		fflush(stdout);

		/* Workaround needed for tests parsing stdout */
		usleep(100000);

		write(STDOUT_FILENO, data, _len);
	}

	if ((ret = TO_fini()) != TO_OK) {
		fprintf(stderr, "TO_fini failed\n");
		exit(1);
	}

	close(_ctx.sock);
	return 0;
}

#else
#error TLS helper need to be built in order to compile tls_handshake.c example
#endif
