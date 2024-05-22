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
 * @file ecies_fd.c
 * @brief ECIES example file descriptor transport (compatible with sockets,
 * fifo, serial devices, etc.).
 */

#include "ecies.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int send_fd = -1;
static int recv_fd = -1;

/**
 * Simple example of initialization function with file descriptors from command
 * line.
 * Example:
 *  mkfifo fifo1
 *  mkfifo fifo2
 *  ecies fifo1 fifo2
 */
int init_data(int argc, const char *argv[])
{
	int ret = -1;

	if (argc != 3) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "\t%s <send device> <recv device>\n", argv[0]);
		goto fail;
	}

#ifdef TO_ECIES_CLIENT
	/* Open file descriptor to send */
	if ((send_fd = open(argv[1], O_WRONLY)) < 0) {
		fprintf(stderr, "open() failed\n");
		goto fail1;
	}
	/* Open file descriptor to receive */
	if ((recv_fd = open(argv[2], O_RDONLY)) < 0) {
		fprintf(stderr, "open() failed\n");
		goto fail1;
	}
#else
	/* Open file descriptor to receive */
	if ((recv_fd = open(argv[2], O_RDONLY)) < 0) {
		fprintf(stderr, "open() failed\n");
		goto fail1;
	}
	/* Open file descriptor to send */
	if ((send_fd = open(argv[1], O_WRONLY)) < 0) {
		fprintf(stderr, "open() failed\n");
		goto fail1;
	}
#endif

	return 0;

fail1:
	fini_data();
fail:
	return ret;
}

int fini_data(void)
{
	int ret = -1;

	if (send_fd != -1) {
		close(send_fd);
	}

	if (recv_fd != -1) {
		close(recv_fd);
	}

	ret = 0;

	return ret;
}

/**
 * Simple example of send function through a regular file descriptor.
 * This function can be replaced with any function which allows to send data.
 */
int send_data(const uint8_t *data, const uint16_t data_len)
{
	fprintf(stdout, "Sending %u bytes\n", data_len);

	if (write(send_fd, data, data_len) != data_len) {
		fprintf(stderr, "write() failed\n");
		return -1;
	}

	fprintf(stdout, "%u bytes sent\n", data_len);

	return 0;
}

/**
 * Simple example of receive function through a regular file descriptor.
 * This function can be replaced with any function which allows to receive data.
 */
int recv_data(uint8_t *data, const uint16_t max_len, uint16_t *data_len)
{
	int32_t len;
	uint16_t data_size;
	uint16_t total_len = 0;

	fprintf(stdout, "Receiving %u bytes\n", max_len);

	/* Read header to get data size */
	while (total_len < HEADER_SIZE) {
		if ((len = read(recv_fd, data + total_len, HEADER_SIZE - total_len))
				< 0) {
			fprintf(stderr, "read() failed\n");
			return -1;
		}
		total_len += len;
	}

	data_size = DATA_SIZE((payload_t*)data);

	/* Read data */
	while (total_len < HEADER_SIZE + data_size) {
		if ((len = read(recv_fd, data + total_len, HEADER_SIZE + data_size
						- total_len)) < 0) {
			fprintf(stderr, "read() failed\n");
			return -1;
		}
		total_len += len;
	}

	fprintf(stdout, "%u bytes received\n", total_len);

	*data_len = total_len;

	return 0;
}
