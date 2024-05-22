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
 * @file core.h
 * @brief TO library internals definitions and functions.
 */

#ifndef _TO_INTERNALS_H_

#include <stdlib.h>
#include <TO_stdint.h>
#include <TO.h>
#include <TO_cmd.h>
#include <TO_i2c_wrapper.h>
#include <TO_endian.h>

/* Internal I/O buffer size */
#ifndef TO_LIB_INTERNAL_IO_BUFFER_SIZE
#define TO_LIB_INTERNAL_IO_BUFFER_SIZE 640
#endif
#if TO_LIB_INTERNAL_IO_BUFFER_SIZE \
	< (TO_CMDHEAD_SIZE + TO_INDEX_SIZE + TO_INDEX_SIZE \
			+ TO_INITIALVECTOR_SIZE + TO_MAXSIZE \
			+ TO_HMAC_SIZE)
#warning Internal IO buffer size may be insufficient
#endif

/**
 * Internal I/O buffer used to send commands to Secure Element and to recieve
 * responses
 */
extern unsigned char TO_io_buffer[TO_LIB_INTERNAL_IO_BUFFER_SIZE];

#ifdef TO_DEBUG
#include <stdio.h>
#define FPRINTF(f, ...) { fprintf(f, __VA_ARGS__); fflush(f); }

/**
 * hex_disp() - Display data using hexadecimal format
 * @data: Data buffer to display
 * @size: Data buffer size
 */
void hex_disp(const uint8_t *data, unsigned int size);

/**
 * dump_buffer() - Dump buffer content, clearly formatted
 * @buf: Data buffer to dump
 * @size: Data buffer size
 */
void dump_buffer(const uint8_t *buf, unsigned int size);

#define HEX_DISP(data, size) { hex_disp(data, size); }
#define HEX_DISP_NB_COL 16
#define HEX_DISP_MAX_DISP_SIZE 32*100
#define DUMP_BUFFER(data, size) { dump_buffer(data, size); }

#else /* TO_DEBUG */

#define FPRINTF(f, ...)
#define HEX_DISP(data, size)
#define DUMP_BUFFER(data, size)

#endif /* TO_DEBUG */

#endif

/**
 * secure_memcmp() - Performs memory areas comparisons in constant time
 * @s1: First memory area
 * @s2: Second memory area
 * @n: Size to compare in bytes
 *
 * Performs s1 and s2 comparisons in constant time (not related to the number
 * of equal bytes).
 *
 * @return value is zero only if s1 and s2 bytes are matching. If n is zero
 * then zero is returned.
 */
int secure_memcmp(const void *s1, const void *s2, unsigned int n);

/**
 * secure_memcpy() - Copy memory area into another safer than memcpy()
 * @dest: Destination memory area
 * @src: Source memory area
 * @n: Size to copy in bytes
 *
 * Copy src to dest after the following checks:
 * - dest and src are not NULL
 * - no overlap between dest and src
 *
 * @return a pointer to dest or NULL on error
 */
void *secure_memcpy(void *dest, const void *src, unsigned int n);

/**
 * secure_memmove() - Move memory area into another safer than memmove()
 * @dest: Destination memory area
 * @src: Source memory area
 * @n: Size to move in bytes
 *
 * Move src to dest after the following checks:
 * - dest and src are not NULL
 * - overlap determines moving from start or from end
 *
 * @return a pointer to dest or NULL on error
 */
void *secure_memmove(void *dest, const void *src, unsigned int n);

/**
 * secure_memset() - Secure memory area set
 * @s: Memory area to set
 * @c: Value to set for each byte of memory area s
 * @n: Length to set
 *
 * Set all bytes of s to c, and prevent this operation to be optimized by
 * compiler.
 * Return immediately if s is NULL.
 *
 * @return s
 */
void *secure_memset(void *s, int c, unsigned int n);
