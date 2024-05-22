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
 * @file seclink.c
 * @brief Secure link common stuff.
 */

#include <TO.h>
#include <seclink.h>
#include <stddef.h>

TO_seclink_store_keys_cb _seclink_store_keys_cb_p = NULL;
TO_seclink_load_keys_cb _seclink_load_keys_cb_p = NULL;

void TO_seclink_set_store_keys_cb(TO_seclink_store_keys_cb cb)
{
	_seclink_store_keys_cb_p = cb;
}

void TO_seclink_set_load_keys_cb(TO_seclink_load_keys_cb cb)
{
	_seclink_load_keys_cb_p = cb;
}

int TO_seclink_request_renewed_keys(void)
{
	return TO_seclink_renew_keys();
}
