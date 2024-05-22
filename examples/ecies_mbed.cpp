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
 * @file ecies_mbed.cpp
 * @brief ECIES example Mbed UART transport.
 */

#include "ecies.h"

#include <stdio.h>

#include "mbed.h"

#if defined(TARGET_DISCO_L072CZ_LRWAN1)
UARTSerial uart(PA_9, PB_7);
#elif defined(TARGET_NUCLEO_L152RE)
UARTSerial uart(PA_9, PA_10);
#else
#error "You must define UART pins for your platform"
#endif

int init_data(int argc __attribute__((unused)),
		const char *argv[] __attribute__((unused)))
{
	return 0;
}

int fini_data(void)
{
	return 0;
}

/**
 * Simple example of send function through mbed UART.
 * This function can be replaced with any function which allows to send data.
 */
int send_data(const uint8_t *data, const uint16_t data_len)
{
	int32_t len;

	fprintf(stdout, "Sending %u bytes\n", data_len);

	if ((len = uart.write(data, data_len)) != data_len) {
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
		if ((len = uart.read(data + total_len, HEADER_SIZE - total_len)) < 0) {
			fprintf(stderr, "read() failed\n");
			return -1;
		}
		total_len += len;
	}

	data_size = DATA_SIZE((payload_t*)data);

	/* Read data */
	while (total_len < HEADER_SIZE + data_size) {
		if ((len = uart.read(data + total_len, HEADER_SIZE + data_size
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
