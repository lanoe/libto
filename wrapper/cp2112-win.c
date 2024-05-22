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
 * @file cp2112-win.c
 * @brief Windows I2C wrapper for CP2112.
 *
 * CP2112 Windows I2C wrapper, using SLABCP2112 library.
 */

#include <stdio.h>
#include <unistd.h>
#include <TO_i2c_wrapper.h>
#include <windows.h>
#include "SLABCP2112.h"

#define TO_CP2112_VID 0x10C4 /* USB vendor ID used by CP2112 device */
#define TO_CP2112_PID 0xEA90 /* USB product ID used by CP2112 device */

#define TO_CP2112_OK 0
#define TO_CP2112_ENUM_FAILED -1
#define TO_CP2112_NOT_CONNECTED -2
#define TO_CP2112_OPEN_FAILED -3
#define TO_CP2112_WRITE_FAILED -4
#define TO_CP2112_READ_FAILED -5
#define TO_CP2112_RESET_FAILED -6
#define TO_CP2112_CLOSE_FAILED -7

#define TO_CP2112_MAX_READ 512 /* Maximum length for read buffer */
#define TO_CP2112_DELAY 1 /* Delay between each retry */
#define TO_CP2112_MAX_RETRY 10000 /* Maximum number of retries */
#define TO_CP2112_OPEN_DELAY 1000 /* Delay between each retry (ms) */
#define TO_CP2112_OPEN_RETRY 10 /* Number of retries before failure */

#define BITRATE (400 * 1000)

static unsigned char i2c_addr = 0x50; /* Secure Element I2C address */
static HID_SMBUS_DEVICE device;

int TO_LED_enable_I2C();

int data_config(int bitRate,int writeTimeout, int readTimeout,
		int sclLowTimeout, int transferRetries, int responseTimeout)
{
	BOOL opened;
	HID_SMBUS_STATUS status;
	
	if (HidSmbus_IsOpened(device, &opened) == HID_SMBUS_SUCCESS && opened) {
		status = HidSmbus_SetSmbusConfig(device, bitRate, 0x02, FALSE,
		writeTimeout, readTimeout, sclLowTimeout, transferRetries);
		if (status != HID_SMBUS_SUCCESS) {
			fprintf(stderr, "HidSmbus_SetSmbusConfig failed "
					"with status %d\n", status);
			return TO_ERROR;
		}
		status = HidSmbus_SetTimeouts(device, responseTimeout);
		if (status != HID_SMBUS_SUCCESS) {
			fprintf(stderr, "HidSmbus_SetTimeouts failed "
					"with status %d\n", status);
			return TO_ERROR;
		}
		return TO_OK;
	} else {
		fprintf(stderr, "HidSmbus_IsOpened failed: "
				"device not opened\n");
		return TO_ERROR;
	}
}

int TO_data_init(void)
{
	HID_SMBUS_STATUS status;
	DWORD num_devices;
	int retry = 0;

	status = HidSmbus_GetNumDevices(&num_devices, TO_CP2112_VID,
			 TO_CP2112_PID);
	if (HID_SMBUS_SUCCESS != status) {
		fprintf(stderr, "Failed to get number of connected devices\n");
		return TO_CP2112_ENUM_FAILED;
	}
	if (num_devices == 0) {
		fprintf(stderr, "Device not connected\n");
		return TO_CP2112_NOT_CONNECTED;
	}

	/* ** Reset Sequence, we open first found device */
	status = HidSmbus_Open(&device, 0, TO_CP2112_VID, TO_CP2112_PID);
	if (HID_SMBUS_SUCCESS != status) {
		fprintf(stderr, "Failed to open CP2112 for reset\n");
		return TO_CP2112_OPEN_FAILED;
	}

	/* Reset the CP2112 to clear communication stacked */
	status = HidSmbus_Reset(device);
	if (status != HID_SMBUS_SUCCESS) {
		fprintf(stderr, "Failed to reset CP2112 (0x%02X)\n", status);
		return TO_CP2112_RESET_FAILED;
	}
	Sleep(2*TO_CP2112_OPEN_DELAY);

	/* Close the device */
	status = HidSmbus_Close(device);
	if (status != HID_SMBUS_SUCCESS) {
		fprintf(stderr, "Failed to close for reset CP2112 for reset "
				"(0x%02X)\n", status);
		return TO_CP2112_CLOSE_FAILED;
	}

	do {
		status = HidSmbus_GetNumDevices(&num_devices,
				TO_CP2112_VID, TO_CP2112_PID);
		if (status == HID_SMBUS_SUCCESS) {
			if (num_devices != 0) {
				status = HidSmbus_Open(&device, 0,
						TO_CP2112_VID,
						TO_CP2112_PID);
				if (status != HID_SMBUS_SUCCESS) {
					fprintf(stderr, "Error: Failed to open "
							"CP2112 device\n");
					Sleep(TO_CP2112_OPEN_DELAY);
				}
			} else {
				Sleep(TO_CP2112_OPEN_DELAY);
			}
		} else {
			Sleep(TO_CP2112_OPEN_DELAY);
		}
	} while((status != HID_SMBUS_SUCCESS) &&
			(retry++ < TO_CP2112_OPEN_RETRY));
	if (retry >= TO_CP2112_OPEN_RETRY) {
		fprintf(stderr, "Error: failed to open CP2112 device after %d"
				"retries\n", retry);
		return TO_ERROR;
	}
	Sleep(2 * TO_CP2112_DELAY);

	TO_LED_enable_I2C();
		
	return data_config(BITRATE, 0, 0, 0, 1, 0);
}

int TO_data_fini(void)
{
	BOOL opened;
	HID_SMBUS_STATUS status;

	status = HidSmbus_IsOpened(device, &opened);
	if (HID_SMBUS_SUCCESS != status) {
		fprintf(stderr, "Error: failed to close CP2112 device: "
				"unable to check if device is opened\n");
		return TO_ERROR;
	}
	if (opened) {
		status = HidSmbus_Close(device);
		if (HID_SMBUS_SUCCESS != status) {
			fprintf(stderr, "Error: failed to close CP2112 "
					"device\n");
			return TO_ERROR;
		}
	}

	return TO_OK;
}

#ifdef TO_I2C_WRAPPER_CONFIG
int TO_data_config(const TO_i2c_config_t *config)
{
	BOOL opened;

	i2c_addr = config->i2c_addr;
	if (HidSmbus_IsOpened(device, &opened) == HID_SMBUS_SUCCESS && opened) {
		if (TO_data_fini() != TO_OK)
			return TO_ERROR;
		if (TO_data_init() != TO_OK)
			return TO_ERROR;
	}

	return TO_OK;
}
#endif

int TO_data_read(void *data, unsigned int length)
{
	unsigned int remaining = length;
	unsigned int retry = 0;
	HID_SMBUS_STATUS status;
	HID_SMBUS_S0 s0;
	HID_SMBUS_S1 s1;
	WORD num_retries;
	WORD bytes_read;
	BYTE read_buf[64]; /* HidSmbus_GetReadResponse requires a buffer of at
			      least 61 bytes */
	BYTE *tmpbuf = data;

	if (length > TO_CP2112_MAX_READ) {
		fprintf(stderr, "Error: maximum buffer read length is %d "
				"(%d requested)\n",
				TO_CP2112_MAX_READ, length);
		return TO_ERROR;
	}
	if (0 == length)
		return TO_OK;

	status = HidSmbus_ReadRequest(device, i2c_addr << 1, length);
	if (HID_SMBUS_SUCCESS != status) {
		fprintf(stderr, "Error: CP2112 ReadRequest failed\n");
		return TO_ERROR;
	}

	while(retry < TO_CP2112_MAX_RETRY) {
		if (retry && (s0 != HID_SMBUS_S0_BUSY)) {
			Sleep(TO_CP2112_DELAY);
			fprintf(stderr, "Error: failed to read from CP2112 "
					"device, retry %d...\n", retry);
		}

		status = HidSmbus_TransferStatusRequest(device);
		if (HID_SMBUS_SUCCESS != status) {
			fprintf(stderr, "Error: CP2112 TrransferStatusRequest "
					"failed\n");
		}

		/* Wait for transfer to finish */
		status = HidSmbus_GetTransferStatusResponse(device, &s0, &s1,
				&num_retries, &bytes_read);
		if (HID_SMBUS_SUCCESS != status)
			fprintf(stderr, "Error: CP2112 "
					"GetTransferStatusResponse failed\n");
		if ((s0 == HID_SMBUS_S0_IDLE)
				|| (s0 == HID_SMBUS_S0_COMPLETE)) {
			retry = 0;
			break;
		}
		if (s0 == HID_SMBUS_S0_ERROR)
			fprintf(stderr, "Error: CP2112 read error\n");
		if (s0 == HID_SMBUS_S0_BUSY)
			Sleep(TO_CP2112_DELAY);
		retry++;
	}
	if (retry >= TO_CP2112_MAX_RETRY) {
		fprintf(stderr, "Error: CP2112 maximum number of retries "
				"reached: %d\n", retry);
		if (s0 == HID_SMBUS_S0_BUSY)
			fprintf(stderr, "Error: bus was busy\n");
		return TO_ERROR;
	}

	/* We need to use ForceReadResponse since autoRead is not set by
	 * default */
	status = HidSmbus_ForceReadResponse(device, bytes_read);
	if (HID_SMBUS_SUCCESS != status) {
		fprintf(stderr, "Error: CP2112 ForceReadResponse failed\n");
		return TO_ERROR;
	}

	retry = 0;
	remaining = bytes_read;
	while (remaining > 0) {
		BYTE nb_read = 0;
		while (retry < TO_CP2112_MAX_RETRY) {
			if (retry) {
				Sleep(TO_CP2112_DELAY);
				fprintf(stderr, "Error: failed to read from "
						"CP2112 device, retry %d...\n",
						retry);
			}
			status = HidSmbus_GetReadResponse(device, &s0, read_buf,
					sizeof(read_buf), &nb_read);
			if (HID_SMBUS_SUCCESS != status)
				fprintf(stderr, "Error: CP2112 GetReadResponse "
						"failed\n");
			if ((s0 == HID_SMBUS_S0_IDLE)
					|| (s0 == HID_SMBUS_S0_COMPLETE)) {
				retry = 0;
				break;
			}
			if (s0 == HID_SMBUS_S0_BUSY) {
				Sleep(TO_CP2112_DELAY);
			}
			retry++;
		}
		if (retry > TO_CP2112_MAX_RETRY) {
			fprintf(stderr, "Error: CP2112 maximum number of "
					"retries reached: %d\n", retry);
			return TO_ERROR;
		}
		if (0 == nb_read)
			/* No more to read: certainly end of stream */
			return TO_OK;
		/* Copy data to output buffer */
		memcpy(tmpbuf, read_buf, nb_read);
		tmpbuf += nb_read;
		remaining -= nb_read;
		retry = 0;
	}

	return TO_OK;
}

int TO_data_write(const void *data, unsigned int length)
{
	unsigned int remaining = length;
	unsigned int retry = 0;
	BYTE nb = 0;
	HID_SMBUS_STATUS status;
	HID_SMBUS_S0 s0;
	HID_SMBUS_S1 s1;
	WORD num_retries;
	WORD bytes_read;
	BYTE* tmpbuf = (BYTE*)data;

	/* Write is limited to 61 bytes by CP2112 driver */
	if (0 == length)
		/* Nothing to write, return */
		return TO_OK;
	while (remaining > 0) {
		if (remaining > 61) {
			nb = 61;
		}
		else {
			nb = remaining;
		}
		status = HidSmbus_WriteRequest(device, i2c_addr << 1,
				tmpbuf, nb);
		if (HID_SMBUS_SUCCESS != status) {
			fprintf(stderr, "Error: CP2112 WriteRequest failed\n");
			return TO_ERROR;
		}
		while (retry < TO_CP2112_MAX_RETRY) {
			if (retry != 0)
				Sleep(TO_CP2112_DELAY);
			status = HidSmbus_TransferStatusRequest(device);
			if (HID_SMBUS_SUCCESS != status)
				fprintf(stderr, "CP2112 TransferStatusRequest "
						"failed\n");
			status = HidSmbus_GetTransferStatusResponse(device, &s0,
					&s1, &num_retries, &bytes_read);
			if (HID_SMBUS_SUCCESS != status)
				fprintf(stderr, "CP2112 "
						"GetTransferStatusResponse "
						"failed\n");
			if ((s0 == HID_SMBUS_S0_IDLE)
					|| (s0 == HID_SMBUS_S0_COMPLETE)) {
				retry = 0;
				break;
			}
			if (s0 == HID_SMBUS_S0_ERROR)
				fprintf(stderr, "Error: CP2112 write error\n");
			if (s0 == HID_SMBUS_S0_BUSY)
				Sleep(TO_CP2112_DELAY);
			retry++;
		}
		if (retry >= TO_CP2112_MAX_RETRY) {
			fprintf(stderr, "Error: CP2112 maximum number of "
					"retries reached: %d\n", retry);
			if (s0 == HID_SMBUS_S0_BUSY)
				printf("Error: bus was busy\n");
			return TO_ERROR;
		}
		remaining -= nb;
		retry = 0;
		tmpbuf += nb;
	}

	return TO_OK;
}


/**** LED configuration ****/

int TO_configure_gpio(unsigned char direction, unsigned char mode,
		unsigned char function, unsigned char clkDiv)
{
	return HidSmbus_SetGpioConfig(device, direction, mode, function, clkDiv);
}

int TO_set_gpio(unsigned char latchValue, unsigned char latchMask)
{
	return HidSmbus_WriteLatch(device, latchValue, latchMask);
}

int TO_LED_enable_I2C()
{
	TO_configure_gpio(0b00001111,0b00001111,0b00000110,0b00000000);
	return TO_set_gpio(0b00001100, 0b00001100); // Red and Green LEDs OFF
}

int TO_LED_reset()
{
	TO_configure_gpio(0x0F, 0x0F, 0, 0);
	return TO_set_gpio(0xFF, 0x0F);
}

int TO_LED_fail()
{
	TO_configure_gpio(0x0F, 0x0F, 0, 0);
	return TO_set_gpio(0b00000100, 0b00001100); // Green: OFF, Red: ON
}

int TO_LED_OK() {
	TO_configure_gpio(0x0F, 0x0F, 0, 0);
	return TO_set_gpio(0b00001000, 0b00001100); // Green: ON, Red: OFF
}
