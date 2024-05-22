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
 * @file get_sn
 * @brief Example getting and printing Secure Element serial number.
 */

#include <stdio.h>
#include <unistd.h>
#include <TO.h>

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
