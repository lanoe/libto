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
 * @file TO_stdint.h
 * @brief Integer types used by libTO, it is a subset of specification ISO/IEC
 * 9899, chapter 7.18 "Integer types".
 */

#ifndef _TO_STDINT_H_
#define _TO_STDINT_H_

#if !HAVE_NO_STDINT_H
#include <stdint.h>
#elif !defined _STDINT_H

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;

#if !defined ( __cplusplus) || defined (__STDC_LIMIT_MACROS)
#define INT8_MIN (-128)
#define INT16_MIN (-32768)
#define INT32_MIN (-2147483648)
#define INT8_MAX 127
#define INT16_MAX 32767
#define INT32_MAX 2147483647
#define UINT8_MAX 255U
#define UINT16_MAX 65535U
#define UINT32_MAX 4294967295U
#endif

#endif /* HAVE_STDINT_H */

#endif /* _TO_STDINT_H_ */
