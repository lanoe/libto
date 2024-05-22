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
 * @file ecies.h
 * @brief ECIES example common defines and transport interface.
 */

#ifndef __ECIES_H__
#define __ECIES_H__

#include <stdint.h>

#include <TO_endian.h>

/**
 * Simple payload to encapsulate messages. It only contains an additionnal byte
 * to describe message content:
 *
 * +-----------+----------------------+--------+
 * | 1 byte    | 2 bytes              |...     |
 * +-----------+----------------------+--------+
 * | data_type | big-endian data size | data   |
 * +-----------+----------------------+--------+
 *
 * This payload and associated protocol can be easily replaced by a proprietary
 * protocol.
 */
typedef struct __attribute__((packed)) payload_s {
	uint8_t data_type;
	uint16_t data_size;
	uint8_t data[0];
} payload_t;

#define HEADER_SIZE (sizeof(uint8_t) + sizeof(uint16_t))
#define PAYLOAD_SIZE(payload) (HEADER_SIZE + be16toh((payload)->data_size))
#define DATA_SIZE(payload) be16toh((payload)->data_size)

#define ASSERT(x) {                                                            \
	if (!(x)) {                                                                \
		fprintf(stderr, "Assertion failed at %s:%d\n", __func__, __LINE__);    \
		exit(1);                                                               \
	}                                                                          \
}

int init_data(int argc, const char *argv[]);
int fini_data(void);
int send_data(const uint8_t *data, const uint16_t data_len);
int recv_data(uint8_t *data, const uint16_t max_len, uint16_t *data_len);

#endif /* __ECIES_H__ */
