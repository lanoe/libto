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
 * @file crc.c
 * @brief CRC software computation APIs.
 */

#ifndef _TO_CRC_H_
#define _TO_CRC_H_

#define CRC16_SEED 0xFFFF

/**
 * @brief Compute CRC16 CCITT 29B1.
 * @param crc Initial value
 * @param data Data to compute on
 * @param len Data length
 * @param reflect Reflect data bytes and remainder?
 *
 * @return Computed CRC value.
 */
uint16_t crc16_ccitt_29b1(uint16_t crc, uint8_t *data, int len, int reflect);

#endif
