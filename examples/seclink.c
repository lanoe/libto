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
 * @file seclink.c
 * @brief Secure link usage example.
 *
 * This example shows how to use secure link with key renewal mechanism.
 *
 * Key renewal is logged on stdout, but keep in mind when running this example
 * that key renewal may be something rare (it depends on the project
 * constraints).
 * The example loops sending RNG requests to the Secure Element, and sometimes
 * prints out a key renewal notification.
 *
 * WARNING: if running the example as is (without storing key into NVM), you
 * should not forget to write down the last printed secure link keys, else you
 * will be locked out next time you will try to use this Secure Element.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <TO.h>

/* Initial secure link keys, will be overwritten on key renewal event */
#if defined ENABLE_SECLINK_ARC4
/* ARC4 encryption / decryption key */
static uint8_t seclink_keys[TO_ARC4_KEY_SIZE] = {
	0x1f, 0xdd, 0x70, 0xc3, 0xa3, 0xa6, 0xe4, 0x77,
	0x72, 0x9b, 0xab, 0xd2, 0x74, 0x16, 0x9d, 0x89
};
#elif defined ENABLE_SECLINK_AESHMAC
/* AES and HMAC keys concatenated */
static uint8_t seclink_keys[TO_AES_KEYSIZE + TO_HMAC_KEYSIZE] = {
	/* AES key */
	0xEB, 0x29, 0x77, 0x65, 0xF6, 0x63, 0x25, 0x36,
	0x5A, 0x3E, 0x43, 0x7D, 0x9E, 0xF3, 0x28, 0x38,
	/* HMAC key */
	0x9B, 0x9B, 0xB2, 0x39, 0x6E, 0x2A, 0x2B, 0x88,
	0x7A, 0xDE, 0xF7, 0xA8, 0x11, 0x18, 0x77, 0x16
};
#else
#error No suitable secure link protocol enabled to compile seclink.c example
#endif

/**
 * seclink_store_keys_cb() - Save the new secure link keys
 * @param data secure link keys
 *
 * The new key replaces the old one.
 * WARNING: This example function stores the new key in RAM, but a real
 * implementation should store it into a NVM.
 */
int seclink_store_keys_cb(void *data)
{
	unsigned int i;
	printf("################\nRenew secure link keys:\n");
#if defined ENABLE_SECLINK_ARC4
	memcpy(seclink_keys, data, TO_ARC4_KEY_SIZE);
	printf("ARC4:");
	for (i = 0; i < TO_ARC4_KEY_SIZE; i++)
		printf(" %02X", seclink_keys[i]);
#elif defined ENABLE_SECLINK_AESHMAC
	memcpy(seclink_keys, data, TO_AES_KEYSIZE + TO_HMAC_KEYSIZE);
	printf("AES:");
	for (i = 0; i < TO_AES_KEYSIZE; i++)
		printf(" %02X", seclink_keys[i]);
	printf("\nHMAC:");
	for (i = TO_AES_KEYSIZE; i < 2 * TO_ARC4_KEY_SIZE; i++)
		printf(" %02X", seclink_keys[i]);
#endif
	printf("\n################\n");
	return TO_OK;
}

/**
 * seclink_load_keys_cb() - Load secure link keys
 * @param data Pre-allocated buffer to return the key
 *
 * This example function loads the key from the RAM, but a real implementation
 * should load it from a NVM.
 */
int seclink_load_keys_cb(void *data)
{
#if defined ENABLE_SECLINK_ARC4
	memcpy(data, seclink_keys, TO_ARC4_KEY_SIZE);
#elif defined ENABLE_SECLINK_AESHMAC
	memcpy(data, seclink_keys, TO_AES_KEYSIZE + TO_HMAC_KEYSIZE);
#endif
	return TO_OK;
}

int main(void)
{
#ifndef TO_DISABLE_API_GET_RANDOM
	unsigned int i;
	uint8_t random[5];
	int ret;

	if (TO_init() != TO_OK) {
		fprintf(stderr, "Unable to initialize TO\n");
		goto err;
	}
	/* Set secure link callbacks just after initialisation */
	TO_seclink_set_store_keys_cb(seclink_store_keys_cb);
	TO_seclink_set_load_keys_cb(seclink_load_keys_cb);
	printf("Secure Element initialized\nLooping Forever\n");

	do {
		ret = TO_get_random(sizeof(random), random);
	        if (ret == TORSP_SUCCESS) {
			printf("Random number:");
			for (i = 0; i < sizeof(random); i++)
				printf(" %02X", random[i]);
			printf("\n");
		} else {
			fprintf(stderr, "Unable to get random (err %X)\n", ret);
		}
	} while(1);
err:
	return -1;
#else
	fprintf(stderr, "Secure Element RNG API is disabled in libTO\n");
	return 1;
#endif
}
