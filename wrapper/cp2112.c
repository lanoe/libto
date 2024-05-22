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
 * @file cp2112.c
 * @brief I2C wrapper for CP2112
 *
 * CP2112 I2C wrapper, using hid_cp2112 Linux kernel module.
 * The Linux kernel module need to be patched to have the communication with
 * the Secure Element to work properly. Please read inscructions from the
 * library wrapper documentation.
 */

#include <TO_i2c_wrapper.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/i2c-dev.h>
#include <linux/hidraw.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <libudev.h>
#include <linux/limits.h>

#define CP2112_MAX_WRITE 61
#define CP2112_VID 0x10c4
#define CP2112_PID 0xea90
#define CP2112_RESPONSE_TIMEOUT 10000
#define CP2112_XFER_STATUS_RETRIES 10000

static unsigned char i2c_addr = 0x50;
static int i2c_device = -1;
static int hid_device = -1;

/*
 * get_device_path() - Get device path
 * @subsystem: device subsystem (see /sys/class contents)
 * @vendor_id: device USB vendor ID
 * @product_id: device USB product ID
 *
 * Get /dev device path according to given subsystem, vendor ID, and product ID.
 *
 * Return: requested device path on success, else NULL.
 * The lifetime of this path string is bound to the device lifetime.
 */
static const char *get_device_path(const char *subsystem, int vendor_id,
		int product_id)
{
	struct udev *udev = NULL;
	struct udev_enumerate *enumerate = NULL;
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev_device *dev = NULL;
	const char *device_path, *ret_path = NULL;
	int vid, pid;

	/* Use udev to find the hidraw and i2c-dev devices of the CP2112 */
	udev = udev_new();
	if (!udev) {
		fprintf(stderr, "Unable to use udev\n");
		goto err;
	}
	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, subsystem);
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);
	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *syspath;
		/* Get filename of device /sys entry to create a udev_device
		 object used to get /dev device path */
		syspath = udev_list_entry_get_name(dev_list_entry);
		dev = udev_device_new_from_syspath(udev, syspath);
		device_path = udev_device_get_devnode(dev);
		/* In order to get USB device information, get the parent
		device */
		dev = udev_device_get_parent_with_subsystem_devtype(dev, "usb",
				"usb_device");
		if (!dev)
			continue;
		/* Check if vendor ID and product ID are the expected ones */
		vid = strtol(udev_device_get_sysattr_value(dev,"idVendor"),
				NULL, 16);
		pid = strtol(udev_device_get_sysattr_value(dev,"idProduct"),
				NULL, 16);
		udev_device_unref(dev);
		dev = NULL;
		if (vid == vendor_id && pid == product_id) {
			ret_path = device_path;
			break;
		}
	}

err:
	if (dev)
		udev_device_unref(dev);
	if (enumerate)
		udev_enumerate_unref(enumerate);
	if (udev)
		udev_unref(udev);
	return ret_path;
}

/**
 * set_driver_param() - Set hid_cp2112 parameter
 * @param: parameter name
 * @value: parameter value
 *
 * Return: 0 on success, else error
 */
static int set_driver_param(const char *param, int value)
{
	char sysfile[PATH_MAX];
	FILE *sysfd;

	sprintf(sysfile, "/sys/module/hid_cp2112/parameters/%s", param);
	sysfd = fopen(sysfile, "w");
	if (sysfd == NULL) {
		perror("Unable to set CP2112 parameter");
		return -1;
	}
	fprintf(sysfd, "%d", value);
	fclose(sysfd);

	return 0;
}

int TO_data_init(void)
{
	const char *i2c_device_path;
	const char *hid_device_path;
	char smbus_config[] = {
		0x06, /* SMBus config report ID */
		0x00, 0x06, 0x1A, 0x80, /* clock speed (Hz) */
		i2c_addr << 1, /* device address */
		0x00, /* auto send read */
		0x00, 0x00, /* write timeout (0-1000 ms) */
		0x00, 0x00, /* read timeout (0-1000 ms) */
		0x00, /* SCL low timeout enabled (0 or 1) */
		0x00, 0x01, /* retry time (0-1000, 0 = no limit) */
	};

	i2c_device_path = get_device_path("i2c-dev", CP2112_VID, CP2112_PID);
	if (i2c_device_path == NULL) {
		fprintf(stderr, "Unable to find CP2112 I2C device path\n");
		goto err;
	}
	hid_device_path = get_device_path("hidraw", CP2112_VID, CP2112_PID);
	if (hid_device_path == NULL) {
		fprintf(stderr, "Unable to find CP2112 HID device path\n");
		goto err;
	}
	i2c_device = open(i2c_device_path, O_RDWR);
	if (i2c_device == -1) {
		perror(i2c_device_path);
		goto err;
	}
	hid_device = open(hid_device_path, O_RDWR|O_NONBLOCK);
	if (hid_device == -1) {
		perror(hid_device_path);
		goto err;
	}
	/* Maybe useless because already set by SMBus settings */
	if (ioctl(i2c_device, I2C_SLAVE, i2c_addr) != 0) {
		perror("Unable to specify slave address");
		goto err;
	}
	if (ioctl(hid_device, HIDIOCSFEATURE(sizeof(smbus_config)),
				smbus_config) < 0) {
		perror("Unable to send SMBus configuration report");
		goto err;
	}
	/* CP2112 driver settings */
	if (set_driver_param("response_timeout", CP2112_RESPONSE_TIMEOUT) ||
			set_driver_param("xfer_status_retries",
				CP2112_XFER_STATUS_RETRIES)) {
		goto err;
	}
	return TO_OK;
err:
	TO_data_fini();
	return TO_ERROR;
}

int TO_data_fini(void)
{
	int ret;

	ret = TO_OK;
	if (i2c_device > 0 && close(i2c_device) != 0) {
		perror("Unable to close CP2112 I2C device");
		ret = TO_ERROR;
	}
	i2c_device = -1;
	if (hid_device > 0 && close(hid_device) != 0) {
		perror("Unable to clode CP2112 HID device");
		ret = TO_ERROR;
	}
	hid_device = -1;

	return ret;
}

#ifdef TO_I2C_WRAPPER_CONFIG
int TO_data_config(const TO_i2c_config_t *config)
{
	i2c_addr = config->i2c_addr;
	if (i2c_device == -1)
		return TO_OK;
	if (TO_data_fini() != TO_OK)
		return TO_ERROR;
	if (TO_data_init() != TO_OK)
		return TO_ERROR;
	return TO_OK;
}
#endif

int TO_data_read(void *data, unsigned int length)
{
	if (read(i2c_device, (void *)data, length) != length) {
		perror("Failed to read from I2C slave");
		return TO_ERROR;
	}
	return TO_OK;
}

int TO_data_write(const void *data, unsigned int length)
{
	unsigned int write_len, write_index = 0;
	do {
		if (length > CP2112_MAX_WRITE)
			write_len = CP2112_MAX_WRITE;
		else
			write_len = length;
		if (write(i2c_device, data + write_index, write_len)
				!= write_len) {
			perror("Failed to write to I2C slave");
			return TO_ERROR;
		}
		length -= write_len;
		write_index += write_len;
	} while (length);
	return TO_OK;
}
