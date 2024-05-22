/**
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2018 Trusted Objects
 *
 * @file mbed_wrapper.cpp
 * @brief I2C wrapper for MBED
 */

#include "TO.h"
#include "mbed.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <TO_i2c_wrapper.h>

#define TO_I2C_ADDR (0x50 << 1)
#define TO_I2C_BITRATE 400 // kHz
#define TO_I2C_TIMEOUT 6000 // ms

#if defined(TARGET_STM) || defined(TARGET_MCUXpresso_MCUS)
i2c_t i2c;
#else
static I2C TO(I2C_SDA, I2C_SCL);
#endif
static DigitalOut POWER(D2);
static unsigned char i2c_addr = TO_I2C_ADDR;
static Timer t;
static int last_command_duration = -1;

#if defined(TARGET_MCUXpresso_MCUS)
#include "fsl_i2c.h"

static I2C_Type *const i2c_addrs[] = I2C_BASE_PTRS;
static i2c_master_handle_t masterHandle;
static volatile status_t i2cStatus = INT32_MAX;

static void masterCallback(I2C_Type *base, i2c_master_handle_t *handle, status_t status, void *userData)
{
	if (base == i2c_addrs[i2c.instance]
	 && handle == &masterHandle) {
		i2cStatus = status;
	}
}

static int i2c_transfer(void *data, unsigned int length, bool is_read)
{
	i2c_master_transfer_t masterXfer;
	Timer _t;

	memset(&masterXfer, 0, sizeof(masterXfer));

	masterXfer.slaveAddress = i2c_addr >> 1;
	masterXfer.direction = (is_read ? kI2C_Read : kI2C_Write);
	masterXfer.data = (uint8_t*)data;
	masterXfer.dataSize = length;

	i2cStatus = INT32_MAX;

	/* Start asynchronous transfer */
	if (I2C_MasterTransferNonBlocking(i2c_addrs[i2c.instance], &masterHandle, &masterXfer) != kStatus_Success) {
		return TO_ERROR;
	}

	/* Start timer */
	_t.start();

	/* Wait completion flag */
	while (_t.read_us() < TO_I2C_TIMEOUT * 1000 && i2cStatus == INT32_MAX);

	return (i2cStatus == kStatus_Success ? TO_OK : TO_DEVICE_READ_ERROR);
}
#endif

int TO_data_init(void)
{
	POWER = 0;
	/* Wait boot time */
	wait(0.001);
#ifdef TARGET_STM
	I2C1->CR1&=~(I2C_CR1_NOSTRETCH);
#endif
#if defined(TARGET_STM) || defined(TARGET_MCUXpresso_MCUS)
	i2c_init(&i2c, I2C_SDA, I2C_SCL);
	i2c_frequency(&i2c, TO_I2C_BITRATE * 1000);
#else
	TO.frequency(TO_I2C_BITRATE * 1000);
#endif
#if defined(TARGET_MCUXpresso_MCUS)
	I2C_MasterTransferCreateHandle(i2c_addrs[i2c.instance], &masterHandle, masterCallback, NULL);
#endif
	t.start();
	return TO_OK;
}

int TO_data_fini(void)
{
	t.stop();
	POWER = 1;
	return TO_OK;
}

int TO_data_config(const TO_i2c_config_t *config)
{
	i2c_addr = (config->i2c_addr << 1);
	return TO_OK;
}

int TO_data_read(void *data, unsigned int length)
{
#ifdef TARGET_STM
	if (HAL_I2C_Master_Receive(&i2c.i2c.handle, i2c_addr, (uint8_t *)data,
				length, TO_I2C_TIMEOUT) == HAL_OK) {
#elif defined(TARGET_MCUXpresso_MCUS)
	if (i2c_transfer(data, length, true) == TO_OK) {
#else
	if (TO.read(i2c_addr, (char*)data, (int)length, false) == 0) {
#endif
		last_command_duration = t.read_us();
		return TO_OK;
	} else {
		return TO_DEVICE_READ_ERROR;
	}
}

int TO_data_write(const void *data, unsigned int length)
{
	last_command_duration = -1;
	t.reset();
#ifdef TARGET_STM
	if (HAL_I2C_Master_Transmit(&i2c.i2c.handle, i2c_addr, (uint8_t *)data,
				length, TO_I2C_TIMEOUT) == HAL_OK) {
#elif defined(TARGET_MCUXpresso_MCUS)
	if (i2c_transfer((void*)data, length, false) == TO_OK) {
#else
	if (TO.write(i2c_addr, (const char*)data, (int)length, true) == 0) {
#endif
		return TO_OK;
	} else {
		return TO_DEVICE_WRITE_ERROR;
	}
}

int TO_data_last_command_duration(unsigned int *duration)
{
	if (last_command_duration < 0) {
		return TO_ERROR;
	}

	*duration = last_command_duration;
	return TO_OK;
}

#ifdef __cplusplus
}
#endif
