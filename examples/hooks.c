/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2018 Trusted Objects
 */

/**
 * @file hooks.c
 * @brief Example for TO library hooks.
 */

#include <stdio.h>
#include <unistd.h>
#include <TO.h>
#include <TO_cmd.h>

void pre_command_hook(uint16_t cmd, uint16_t cmd_data_len)
{
	printf("PRE COMMAND HOOK: cmd=%04X, len=%04X\n", cmd, cmd_data_len);
	/*
	 * Here we can prepare system suspend, for example by setting wakeup
	 * interrupt for the PIO connected to the secure element status PIO.
	 */
}

void post_write_hook(uint16_t cmd, uint16_t cmd_data_len)
{
	printf("POST WRITE HOOK: cmd=%04X, len=%04X\n", cmd, cmd_data_len);
	/*
	 * Here we can suspend system for a while or until Secure Element
	 * status PIO notifies response readyness, according to command code
	 * or command data length, in order to optimize power consumption.
	 */
}

void post_command_hook(uint16_t cmd, uint16_t cmd_data_len,
		uint16_t cmd_rsp_len, uint8_t cmd_status)
{
	printf("POST COMMAND HOOK: cmd=%04X, len=%04X, "
			"rsp_len=%04X, status=%02X\n",
			cmd, cmd_data_len, cmd_rsp_len, cmd_status);
}

int main(void)
{
#ifndef TO_DISABLE_TO_INFO
	unsigned int i;
	int ret;
	uint8_t serial_number[TO_SN_SIZE];

	if (TO_init() != TO_OK) {
		fprintf(stderr, "Unable to initialize TO\n");
		ret = -1;
		goto err;
	}
	TO_set_lib_hook_pre_command(pre_command_hook);
	TO_set_lib_hook_post_write(post_write_hook);
	TO_set_lib_hook_post_command(post_command_hook);
	printf("Secure Element initialized\n");
	if (TO_get_serial_number(serial_number) != TORSP_SUCCESS) {
		fprintf(stderr, "Unable to get Secure Element serial number\n");
		ret = -2;
		goto err;
	}
	printf("Secure Element serial number:");
	for (i = 0; i < TO_SN_SIZE; i++)
		printf(" %02X", serial_number[i]);
	printf("\n");

	ret = 0;
err:
	TO_fini();
	return ret;
#else
	fprintf(stderr, "Secure Element information APIs are disabled in libTO\n");
	return 1;
#endif
}
