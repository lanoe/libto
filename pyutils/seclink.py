"""
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

Copyright 2017 Trusted Objects

@brief       Secure Element secure link tools
@author      Trusted-Objects
"""

from os import mkdir, remove
from pathlib import Path
import pickle
from ctypes import CFUNCTYPE, c_int, c_void_p, c_char
from TO.const import TO_OK, TO_ERROR, \
        ARC4_KEY_SIZE, AES_KEY_SIZE, HMAC_KEY_SIZE, CONF_DIR
from TO.config import ENABLE_SECLINK_ARC4, ENABLE_SECLINK_AESHMAC
from TO.methods import decode_string, encode_hex

if ENABLE_SECLINK_ARC4:
    DEFAULT_KEYS = bytes(b'\x1f\xdd\x70\xc3\xa3\xa6\xe4\x77' \
            b'\x72\x9b\xab\xd2\x74\x16\x9d\x89')
    SECLINK_ENABLED = 1
    SECLINK_KEYSIZE = ARC4_KEY_SIZE
elif ENABLE_SECLINK_AESHMAC:
    DEFAULT_KEYS = bytes(b'\xEB\x29\x77\x65\xF6\x63\x25\x36' \
            b'\x5A\x3E\x43\x7D\x9E\xF3\x28\x38' \
            b'\x9B\x9B\xB2\x39\x6E\x2A\x2B\x88' \
            b'\x7A\xDE\xF7\xA8\x11\x18\x77\x16')
    SECLINK_ENABLED = 1
    SECLINK_KEYSIZE = AES_KEY_SIZE + HMAC_KEY_SIZE
else:
    SECLINK_ENABLED = 0
    SECLINK_KEYSIZE = 0

def resetkeys():
    """ Resets secure link keys to default.
    """
    try:
        remove(str(Path.home()) + "/" + CONF_DIR + "/seclink_key")
    except FileNotFoundError:
        pass

@CFUNCTYPE(c_int, c_void_p)
def loadkeys_cb(keys):
    """ Try to load the secure link key from HOME/.TOsh/seclink_key", and use
    the default key if none has been previously saved.
    """
    if not SECLINK_ENABLED:
        return TO_OK
    buf = (c_char * SECLINK_KEYSIZE).from_address(keys)
    try:
        loaded_keys = pickle.load(open(str(Path.home()) + "/" + CONF_DIR
            + "/seclink_key", "rb" ))
    except FileNotFoundError:
        loaded_keys = DEFAULT_KEYS
    for i in range(SECLINK_KEYSIZE):
        buf[i] = loaded_keys[i]
    return TO_OK

@CFUNCTYPE(c_int, c_void_p)
def storekeys_cb(keys):
    """ Save the new secure link key to HOME/.TOsh/seclink_key".
    """
    if not SECLINK_ENABLED:
        return TO_OK
    try:
        mkdir(CONF_DIR)
    except FileExistsError:
        pass
    buf = (c_char * SECLINK_KEYSIZE).from_address(keys)
    new_keys = bytearray(SECLINK_KEYSIZE)
    for i in range(SECLINK_KEYSIZE):
        new_keys[i] = buf[i][0]
    pickle.dump(new_keys, open(str(Path.home()) + "/" + CONF_DIR
        + "/seclink_key", "wb"))
    return TO_OK

def setkeys(keys):
    """ Sets secure link keys.
    """
    if len(keys) != SECLINK_KEYSIZE * 2:
        print("Invalid keys length, expected %d hex digits" % SECLINK_KEYSIZE)
        return TO_ERROR
    keys_bytes = decode_string(keys)
    return storekeys_cb(keys_bytes)

def getkeys():
    """ Gets secure link keys.
    """
    keys_bytes = b' ' * SECLINK_KEYSIZE
    loadkeys_cb(keys_bytes)
    return encode_hex(keys_bytes)
