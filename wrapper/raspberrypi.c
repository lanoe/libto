/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2016 Trusted Objects
 */

/**
 * @file raspberrypi.c
 * @brief I2C wrapper for RaspberryPi
 *
 * This wrapper is mainly the same as the generic Linux wrapper, except that it
 * is able to handle Secure Element power control.
 * It is possible to change the default values with the following environment
 * variables:
 * - LIBTO_I2CDEV: Linux I2C device to use
 * - LIBTO_GNDPIN: pin on which the Secure Element GND is connected
 *
 * Warning: due to RaspberryPi hardware I2C stack bug with clock stretching,
 * it is highly recommended to use I2C in bitbanging mode, else most of Secure
 * Element commands will not work.
 * See http://www.advamation.com/knowhow/raspberrypi/rpi-i2c-bug.html to read
 * more about this bug.
 */

#include <TO_i2c_wrapper.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <rpi_gpio.h>
#include <sys/time.h>

#define DEFAULT_I2C_DEV "/dev/i2c-3"
#define DEFAULT_GND_PIN 18
#define DEFAULT_I2C_TIMEOUT 1000

static unsigned char i2c_addr = 0x50;
static unsigned char device_nack_last_byte = 0;
static unsigned char use_power_gpio = 1;
static int i2c_device = -1;
/* To mesure last command duration */
static struct timeval time_before_write, time_after_read;

/**
 * get_i2c_device_path() - Get the path of the I2C device
 *
 * @return Device path pointer
 */
static char * get_i2c_device_path(void)
{
	char *i2c_device_path;
	i2c_device_path = getenv("LIBTO_I2CDEV");
	if (i2c_device_path == NULL)
		i2c_device_path = DEFAULT_I2C_DEV;
	return i2c_device_path;
}

/**
 * get_gnd_pin() - Get the GPIO number of the Secure Element power control
 * line.
 *
 * The returned pin is the Secure Element GND, as the Secure Element power
 * on/off is controlled through GND level.
 *
 * @return Secure Element GND line pin number
 */
static int get_gnd_pin(void)
{
	char *pin_str;
	pin_str = getenv("LIBTO_GNDPIN");
	if (pin_str == NULL)
		return DEFAULT_GND_PIN;
	return atoi(pin_str);
}

int TO_data_init()
{
	char *i2c_device_path;
	int gnd_pin;
	if (use_power_gpio) {
		/* Power on Secure Element by setting its GND power line low */
		if (map_peripheral(&gpio)) {
			fprintf(stderr, "Unable to map GPIO to power on SE\n");
			return TO_ERROR;
		}
		gnd_pin = get_gnd_pin();
		GPIO_IN(gnd_pin);
		GPIO_OUT(gnd_pin);
		GPIO_CLR = 1 << gnd_pin;
		usleep(10000);
	}
	/* Open and configure I2C device */
	i2c_device_path = get_i2c_device_path();
	i2c_device = open(i2c_device_path, O_RDWR);
	if (i2c_device == -1) {
		perror(i2c_device_path);
		return TO_ERROR;
	}
	if (ioctl(i2c_device, I2C_SLAVE, i2c_addr) != 0)
	{
		perror("Unable to specify slave address");
		if (close(i2c_device) != 0)
			perror(i2c_device_path);
		return TO_ERROR;
	}
	if (ioctl(i2c_device, I2C_TIMEOUT, DEFAULT_I2C_TIMEOUT / 10) != 0)
	{
		perror("Unable to set I2C timeout");
		if (close(i2c_device) != 0)
			perror(i2c_device_path);
		return TO_ERROR;
	}
	return TO_OK;
}

int TO_data_fini(void)
{
	int gnd_pin;
	/* Close I2C device */
	if (close(i2c_device) != 0) {
		perror(get_i2c_device_path());
		return TO_ERROR;
	}
	i2c_device = -1;
	if (use_power_gpio) {
		/* Power off Secure Element by setting its GND line high */
		gnd_pin = get_gnd_pin();
		GPIO_SET = 1 << gnd_pin;
		usleep(10000);
		unmap_peripheral(&gpio);
	}
	return TO_OK;
}

#ifdef TO_I2C_WRAPPER_CONFIG
int TO_data_config(const TO_i2c_config_t *config)
{
	int ret = TO_ERROR;

	i2c_addr = config->i2c_addr;
	device_nack_last_byte =
		(config->misc_settings & TO_CONFIG_NACK_LAST_BYTE);
	if (i2c_device != -1) {
		use_power_gpio = 0;
		if (TO_data_fini() != TO_OK)
			goto end;
		if (TO_data_init() != TO_OK)
			goto end;
	}

	ret = TO_OK;
end:
	use_power_gpio = 1;
	return ret;
}
#endif

int TO_data_read(void *data, unsigned int length)
{
	if (read(i2c_device, (void *)data, length) != (int)length) {
		perror("Failed to read from I2C slave");
		return TO_ERROR;
	}
	gettimeofday(&time_after_read, NULL);
	return TO_OK;
}

int TO_data_write(const void *data, unsigned int length)
{
	gettimeofday(&time_before_write, NULL);
	if (write(i2c_device, data, length) != (int)length) {
		/* If last written byte is NAK by device ignore EIO */
                if (errno != EIO || !device_nack_last_byte) {
                        perror("Failed to write to I2C slave");
                        return TO_ERROR;
                }
	}
	return TO_OK;
}

int TO_data_last_command_duration(unsigned int *duration)
{
	struct timeval diff;
	timersub(&time_after_read, &time_before_write, &diff);
	*duration = diff.tv_sec * 1000000 + diff.tv_usec;
	return TO_OK;
}
