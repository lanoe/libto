/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2017 Trusted Objects. All rights reserved.
 */

/**
 * @file TO_endian.h
 * @brief Endianness.
 */

#ifndef _TO_ENDIAN_H_
#define _TO_ENDIAN_H_

#if HAVE_ENDIAN_H
#include <endian.h>
#else

#if defined(__BYTE_ORDER__) \
	&& !defined(TO_BIG_ENDIAN) && !defined(TO_LITTLE_ENDIAN)
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		#define TO_LITTLE_ENDIAN
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		#define TO_BIG_ENDIAN
	#else
		#error "Unsupported byte order"
	#endif
#endif

#if HAVE_BYTESWAP_H
	#include <byteswap.h>
#else
	#define bswap_16(value) \
		((((value) & 0xff) << 8) | ((value) >> 8))
	#define bswap_32(value) \
		(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) \
		  << 16) | (uint32_t)bswap_16((uint16_t)((value) >> 16)))
	#define bswap_64(value) \
		(((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
		  << 32) | (uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif

#ifdef TO_LITTLE_ENDIAN
	#define htobe16(x) bswap_16(x)
	#define htobe32(x) bswap_32(x)
	#define htobe64(x) bswap_64(x)
	#define be16toh(x) bswap_16(x)
	#define be32toh(x) bswap_32(x)
	#define be64toh(x) bswap_64(x)
	#define htole16(x) (x)
	#define htole32(x) (x)
	#define htole64(x) (x)
	#define le16toh(x) (x)
	#define le32toh(x) (x)
	#define le64toh(x) (x)
#elif defined(TO_BIG_ENDIAN)
	#define htobe16(x) (x)
	#define htobe32(x) (x)
	#define htobe64(x) (x)
	#define be16toh(x) (x)
	#define be32toh(x) (x)
	#define be64toh(x) (x)
	#define htole16(x) bswap_16(x)
	#define htole32(x) bswap_32(x)
	#define htole64(x) bswap_64(x)
	#define le16toh(x) bswap_16(x)
	#define le32toh(x) bswap_32(x)
	#define le64toh(x) bswap_64(x)
#else
	/* Runtime detection is needed */
	#define TO_ENDIAN_RUNTIME_DETECT
	#define TO_BYTE_ORDER_LITTLE_ENDIAN 0
	#define TO_BYTE_ORDER_BIG_ENDIAN 1
	extern int TO_byte_order;
	#define htobe16(x) (TO_byte_order ? x : bswap_16(x))
	#define htobe32(x) (TO_byte_order ? x : bswap_32(x))
	#define htobe64(x) (TO_byte_order ? x : bswap_64(x))
	#define be16toh(x) (TO_byte_order ? x : bswap_16(x))
	#define be32toh(x) (TO_byte_order ? x : bswap_32(x))
	#define be64toh(x) (TO_byte_order ? x : bswap_64(x))
	#define htole16(x) (TO_byte_order ? bswap_16(x) : x)
	#define htole32(x) (TO_byte_order ? bswap_32(x) : x)
	#define htole64(x) (TO_byte_order ? bswap_64(x) : x)
	#define le16toh(x) (TO_byte_order ? bswap_16(x) : x)
	#define le32toh(x) (TO_byte_order ? bswap_32(x) : x)
	#define le64toh(x) (TO_byte_order ? bswap_64(x) : x)
#endif

#endif /* HAVE_ENDIAN_H */

#endif /* _TO_ENDIAN_H_ */
