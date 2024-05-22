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
 * @file TO_i2c_wrapper.h
 * @brief I2C abstraction layer.
 *
 * Secure Element API functions from Secure Element.c run by calling TO_data_* APIs,
 * as documented below.
 * These functions implementation depends on the underlying hardware to manage
 * I2C communication bus.
 * Then, for every new hardware to support, the functions below have to be
 * implemented.
 */

#ifndef _TO_I2C_WRAPPER_H_
#define _TO_I2C_WRAPPER_H_

#include <TO_defs.h>

#ifndef TO_IO
#ifdef __linux__
#define TO_IO
#elif _WIN32
#define TO_IO __declspec(dllexport)
#else
#define TO_IO
#endif /* __LINUX__ */
#endif

/**
 * @brief I2C wrapper configuration
 *
 * To be used through TO_data_config().
 */
struct TO_i2c_config_s {
	unsigned char i2c_addr; /**< Device I2C address on 7 bits (MSB=0) */
	unsigned char misc_settings; /**< Misc. device I2C settings bitfield:
	| RES | RES | RES | RES | RES | RES | RES | last byte NACKed | */
};
typedef struct TO_i2c_config_s TO_i2c_config_t;

/** ::TO_i2c_config_s misc. setting:
 * last byte is NACKed by remote device */
#define TO_CONFIG_NACK_LAST_BYTE 0x01

/**
 * @brief Initialize Secure Element communication bus
 *
 * Initializes I2C bus for Secure Element communications.
 *
 * @return TO_OK if initialization was successful, else TO_ERROR
 */
TO_IO int TO_data_init(void);

/**
 * @brief Terminate Secure Element communication bus
 *
 * Reset (stop) I2C bus used for Secure Element communications.
 *
 * @return TO_OK if reset was successful, else TO_ERROR
 */
TO_IO int TO_data_fini(void);

/**
 * @brief I2C configuration (optional function)
 * @param config I2C configuration to use
 *
 * Take given I2C configuration and apply it on the I2C wrapper.
 * If the function returns successfully, it means the configuration has been
 * applied and taken into account.
 * The wrapper must NOT assume this function will be called, and must run
 * correctly even if this function is never used.
 *
 * This function is optional, and even if enabled by TO_I2C_WRAPPER_CONFIG
 * it can still return TO_OK without doing anything. It is left to the
 * wrapper developer discretion.  This function is not called internally by
 * TO library.
 *
 * See ::TO_i2c_config_s.
 *
 * @return TO_OK if configuration has been applied, else TO_ERROR
 */
TO_IO int TO_data_config(const TO_i2c_config_t *config);

/**
 * @brief Read data from Secure Element on I2C bus
 * @param data Buffer to store recieved data
 * @param length Amount of data to read in bytes
 *
 * Reads spacified amount of data from the Secure Element on I2C bus.
 * This function returns when data has been read and is available in the data
 * buffer, or if an error occured.
 * The condition start have to be sent only one time to read the full Secure
 * Element response, the reading can not be divided.
 *
 * @return TO_OK if data has been read sucessfully
 * TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * TO_ERROR if an internal error has occured
 */
TO_IO int TO_data_read(void *data, unsigned int length);

/**
 * @brief Write data to Secure Element on I2C bus
 * @param data Buffer containing data to send
 * @param length Amount of data to send in bytes
 *
 * Writes specified amount of data to the Secure Element on I2C bus.
 * This function returns when all data in the buffer has been written, or if an
 * error occured.
 * The condition start have to be sent only one time to write the full Secure
 * Element command, the writing can not be divided.
 *
 * @return TO_OK if data has been written sucessfully
 * TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * TO_ERROR if an internal error has occured
 */
TO_IO int TO_data_write(const void *data, unsigned int length);

/**
 * @brief Get last command duration (from I2C send to I2C receive)
 * @param duration Pointer to store last command duration in microseconds
 *
 * Measure the delay of the last executed command with MCU point of view.
 * This function is optional, if implemented you have to define
 * TO_I2C_WRAPPER_LAST_COMMAND_DURATION in your project in order to use it
 * through TO_last_command_duration() API.
 *
 * This function should only be called after a successful TO_read() call.
 * If it is called after a failed TO_read(), or after a TO_write() call, the
 * result is unspecified and may be irrelevant.
 *
 * @return TO_OK if last command duration is available
 * TO_ERROR if an internal error has occured
 */
TO_IO int TO_data_last_command_duration(unsigned int *duration);

#endif
