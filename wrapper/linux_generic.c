/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2017 Trusted Objects
 */

/**
 * @file linux_generic.c
 * @brief Generic Linux I2C wrapper.
 */

#include <TO_i2c_wrapper.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define TO_I2C_TIMEOUT 1000

/* Wrapper settings, can be changed through TO_data_config if
 * TO_I2C_WRAPPER_CONFIG is defined */
static unsigned char i2c_addr = 0x50;
static unsigned char device_nack_last_byte = 0;

static int i2c_device = -1;

int TO_data_init()
{
	i2c_device = open(TO_I2C_DEVICE, O_RDWR);
	if (i2c_device == -1) {
		perror(TO_I2C_DEVICE);
		return TO_ERROR;
	}
	if (ioctl(i2c_device, I2C_SLAVE, i2c_addr) != 0)
	{
		perror("Unable to specify slave address");
		if (close(i2c_device) != 0)
			perror(TO_I2C_DEVICE);
		return TO_ERROR;
	}
	if (ioctl(i2c_device, I2C_TIMEOUT, TO_I2C_TIMEOUT / 10) != 0)
	{
		perror("Unable to set I2C timeout");
		if (close(i2c_device) != 0)
			perror(TO_I2C_DEVICE);
		return TO_ERROR;
	}
	return TO_OK;
}

int TO_data_fini(void)
{
	if (close(i2c_device) != 0) {
		perror(TO_I2C_DEVICE);
		return TO_ERROR;
	}
	i2c_device = -1;
	return TO_OK;
}

#ifdef TO_I2C_WRAPPER_CONFIG
int TO_data_config(const TO_i2c_config_t *config)
{
	i2c_addr = config->i2c_addr;
	device_nack_last_byte =
		(config->misc_settings & TO_CONFIG_NACK_LAST_BYTE);
	return TO_OK;
}
#endif

int TO_data_read(void *data, unsigned int length)
{
	if (read(i2c_device, (void *)data, length) != (int)length) {
		perror("Failed to read from I2C slave");
		return TO_ERROR;
	}
	return TO_OK;
}

int TO_data_write(const void *data, unsigned int length)
{
	if (write(i2c_device, data, length) != (int)length) {
		/* If last written byte is NAK by device ignore EIO */
		if (errno != EIO || !device_nack_last_byte) {
			perror("Failed to write to I2C slave");
			return TO_ERROR;
		}
	}
	return TO_OK;
}
