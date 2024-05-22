"""
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

Copyright 2017 Trusted Objects

@brief       Secure Element Python utils: Secure Element API binding
@author      Trusted-Objects
"""

from ctypes import byref, c_char_p, c_int, c_ubyte, c_uint32
from TO.methods import register, decode_string, encode_hex
from TO.const import *
from TO.config import *
from TO.seclink import *

global libTO

def __init__(library):
    global libTO
    libTO = library

@register('TO_INIT',
        labels={'lib': 'libTO', 'category':'Lib', 'description':'',
            'order': 1})
def TO_init():
    ret = libTO.TO_init()
    libTO.TO_seclink_set_load_keys_cb(loadkeys_cb)
    libTO.TO_seclink_set_store_keys_cb(storekeys_cb)
    return ret

@register('TO_FINI',
        labels={'lib': 'libTO', 'category':'Lib', 'description':'',
            'order': 2})
def TO_fini():
    return libTO.TO_fini()

@register('TO_READ',
        labels={'lib': 'libTO', 'category':'Lib','description':'',
            'order': 3})
def TO_read(length):
    data = b' ' * length
    ret = libTO.TO_read(c_char_p(data), length)
    return ret, encode_hex(data)

@register('TO_WRITE',
        labels={'lib': 'libTO', 'category':'Lib','description':'',
            'order': 4})
def TO_write(data):
    databytes = decode_string(data)
    return libTO.TO_write(c_char_p(databytes), len(databytes))

@register('TO_CONFIG',
        labels={'lib': 'libTO', 'category':'Lib','description':'',
            'order': 5})
def TO_config(i2c_addr, misc_settings):
    i2c_addr_b = decode_string(i2c_addr)[0]
    misc_settings_b = decode_string(misc_settings)[0]
    return libTO.TO_config(c_ubyte(i2c_addr_b),
            c_ubyte(misc_settings_b))

@register('TO_SECLINK_BYPASS',
        labels={'lib': 'libTO', 'category':'Lib','description':'',
            'order': 6})
def TO_seclink_bypass(bypass):
    libTO.TO_seclink_bypass(bypass)

@register('TO_LAST_COMMAND_DURATION',
        labels={'lib': 'libTO', 'category':'Lib','description':'',
            'order': 7})
def TO_last_command_duration():
    duration = c_uint32()
    ret = libTO.TO_last_command_duration(byref(duration))
    return {'status': hex(ret)[2:], 'duration': duration.value}

if not DISABLE_TO_INFO:
    @register('GET_SN',
            out_params={'serial_number': 'hex'},
            labels={'category': 'System'})
    def TO_get_serial_number():
        sn = b' ' * 8
        ret = libTO.TO_get_serial_number(c_char_p(sn))
        return {'status': hex(ret)[2:], 'serial_number': encode_hex(sn)}

    @register('GET_PN',
            out_params={'product_number': 'str'},
            labels={'category': 'System',
                'order': 2})
    def TO_get_product_number():
        pn = b' ' * 12
        ret = libTO.TO_get_product_number(c_char_p(pn))
        return {'status': hex(ret)[2:], 'product_number': pn.decode("utf-8")}

    @register('GET_HW_VERSION',
            out_params={'hardware_version': 'hex'},
            labels={'category': 'System'})
    def TO_get_hardware_version():
        hw = b' ' * 2
        ret = libTO.TO_get_hardware_version(c_char_p(hw))
        return {'status': hex(ret)[2:], 'hardware_version': encode_hex(hw)}

    @register('GET_SW_VERSION',
            out_params={'major': 'uint8', 'minor': 'uint8',
                'revision': 'uint8'},
            labels={'category': 'System'})
    def TO_get_software_version():
        swmaj = c_int()
        swmin = c_int()
        swrev = c_int()
        ret = libTO.TO_get_software_version(byref(swmaj), byref(swmin),
                byref(swrev))
        return {'status': hex(ret)[2:], 'major': swmaj.value,
                'minor': swmin.value, 'revision': swrev.value}

if not DISABLE_API_GET_RANDOM:
    @register('GET_RANDOM',
            in_params={'random_length': 'uint16'},
            out_params={'random': 'hex'},
            labels={'category': 'System'})
    def TO_get_random(params):
        random_length = params['random_length']
        value = b' ' * random_length
        ret = libTO.TO_get_random(random_length, c_char_p(value))
        return {'status': hex(ret)[2:], 'random': encode_hex(value)}

if not DISABLE_STATUS_PIO_CONFIG:
    @register('GET_STATUS_PIO_CONFIG',
            out_params={'enable': 'int', 'opendrain': 'int',
                'ready_level': 'int', 'idle_hz': 'int'},
            labels={'category': 'System'})
    def TO_get_status_PIO_config():
        enable = c_int()
        opendrain = c_int()
        ready_level = c_int()
        idle_hz = c_int()
        ret = libTO.TO_get_status_PIO_config(byref(enable), byref(opendrain),
                byref(ready_level), byref(idle_hz))
        return {'status': hex(ret)[2:], 'enable': enable.value,
                'opendrain': opendrain.value, 'ready_level': ready_level.value,
                'idle_hz': idle_hz.value}

    @register('SET_STATUS_PIO_CONFIG',
            in_params={'enable': 'int', 'opendrain': 'int',
                'ready_level': 'int', 'idle_hz': 'int'},
            labels={'category': 'System'})
    def TO_set_status_PIO_config(params):
        enable = params['enable']
        opendrain = params['opendrain']
        ready_level = params['ready_level']
        idle_hz = params['idle_hz']
        ret = libTO.TO_set_status_PIO_config(enable, opendrain, ready_level,
                idle_hz)
        return {'status': hex(ret)[2:]}

if not DISABLE_SHA256:
    @register('SHA256', in_params={'data': 'hex'},
            out_params={'sha256': 'hex'},
            labels={'category': 'Hash'})
    def TO_sha256(params):
        data = decode_string(params['data'])
        sha256 = b' ' * 32
        ret = libTO.TO_sha256(c_char_p(data), len(data), c_char_p(sha256))
        return {'status': hex(ret)[2:], 'sha256': encode_hex(sha256)}

    @register('SHA256_INIT',
            labels={'category': 'Hash'})
    def TO_sha256_init():
        ret = libTO.TO_sha256_init()
        return {'status': hex(ret)[2:]}

    @register('SHA256_UPDATE', in_params={'data': 'hex'},
            labels={'category': 'Hash'})
    def TO_sha256i_update(params):
        data = decode_string(params['data'])
        ret = libTO.TO_sha256_update(c_char_p(data), len(data))
        return {'status': hex(ret)[2:]}

    @register('SHA256_FINAL',
            out_params={'sha256': 'hex'},
            labels={'category': 'Hash'})
    def TO_sha256_final():
        sha256 = b' ' * 32
        ret = libTO.TO_sha256_final(c_char_p(sha256))
        return {'status': hex(ret)[2:], 'sha256': encode_hex(sha256)}

if not DISABLE_CERT_MGMT:
    def TO_raw_to_dict(cert):
        ret = {}
        ret['cert.ca_id'] = encode_hex(cert[0:3])
        ret['cert.serial'] = encode_hex(cert[3:8])
        ret['cert.key'] = encode_hex(cert[8:72])
        ret['cert.signature'] = encode_hex(cert[72:])
        return ret

    @register('GET_CERTIFICATE_SUBJECT_CN',
            in_params={'index': 'uint8'},
            out_params={'subject_cn': 'hex'},
            labels={'category': 'Authentication'})
    def TO_get_certificate_subject_cn(params):
        data = b' ' * TO_CERT_SUBJECT_CN_MAXSIZE
        ret = libTO.TO_get_certificate_subject_cn(params['index'], c_char_p(data))
        res = {'status': hex(ret)[2:], 'subject_cn': data}
        return res

    @register('GET_CERTIFICATE',
            in_params={'index': 'uint8'},
            out_params={'cert.ca_id': 'hex', 'cert.serial': 'hex',
                'cert.key': 'hex', 'cert.signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_get_certificate(params):
        data = b' ' * TO_CERT_SIZE
        ret = libTO.TO_get_certificate(params['index'], 1, c_char_p(data))
        res = {'status': hex(ret)[2:], }
        res.update(TO_raw_to_dict(data))
        return res

    @register('GET_CERTIFICATE_X509',
            in_params={'index': 'uint8'},
            out_params={'cert': 'hex'},
            labels={'category': 'Authentication'})
    def TO_get_certificate_x509(params):
        data = b' ' * TO_MAXSIZE
        size = c_int()
        ret = libTO.TO_get_certificate_x509(params['index'], c_char_p(data),
                byref(size))
        cert = encode_hex(data)[:size.value * 2]
        res = {'status': hex(ret)[2:], 'cert': cert}
        return res

    @register('GET_CERTIFICATE_AND_SIGN',
            in_params={'index': 'uint8', 'challenge': 'hex'},
            out_params={'cert.ca_id': 'hex', 'cert.serial': 'hex',
                'cert.key': 'hex', 'cert.signature': 'hex', 'signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_get_certificate_and_sign(params):
        challenge = decode_string(params['challenge'])
        data = b' ' * TO_CERT_SIZE
        signature = b' ' * SIGNATURE_SIZE
        ret = libTO.TO_get_certificate_and_sign(params['index'], 1,
                c_char_p(challenge), len(challenge), c_char_p(data),
                c_char_p(signature))
        res = {'status': hex(ret)[2:], 'signature': encode_hex(signature)}
        res.update(TO_raw_to_dict(data))
        return res

    @register('GET_CERTIFICATE_X509_AND_SIGN',
            in_params={'index': 'uint8', 'challenge': 'hex'},
            out_params={'cert': 'hex', 'signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_get_certificate_x509_and_sign(params):
        challenge = decode_string(params['challenge'])
        data = b' ' * TO_MAXSIZE
        size = c_int()
        signature = b' ' * SIGNATURE_SIZE
        ret = libTO.TO_get_certificate_x509_and_sign(params['index'],
                c_char_p(challenge), len(challenge), c_char_p(data),
                byref(size), c_char_p(signature))
        cert = encode_hex(data)[:size.value * 2]
        res = {'status': hex(ret)[2:], 'cert': cert,
                'signature': encode_hex(signature)}
        res.update(TO_raw_to_dict(data))
        return res

    @register('VERIFY_CERTIFICATE_AND_STORE',
            in_params={'ca_key_index': 'uint8', 'format': 'uint8',
                'cert.ca_id': 'hex', 'cert.serial': 'hex', 'cert.key': 'hex',
                'cert.signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_verify_certificate_and_store(params):
        cert_format = int(params['format'])
        cert_raw = decode_string(params['cert_raw'])
        if cert_format == TOCERTF_STANDALONE and len(cert_raw) != 136:
            print("Wrong size for standalone certificate")
            return {'status': -100}
        if cert_format == TOCERTF_SHORT_V2 and len(cert_raw) != 158:
            print("Wrong size for short v2 certificate")
            return {'status': -100}
        ret = libTO.TO_verify_certificate_and_store(
            params['ca_key_index'], cert_format,  c_char_p(cert_raw))
        return {'status': hex(ret)[2:]}

    @register('VERIFY_CA_CERTIFICATE_AND_STORE',
            in_params={'ca_key_index': 'uint8', 'subca_key_index': 'uint8',
                'certificate': 'hex'},
            labels={'category': 'Authentication'})
    def TO_verify_ca_certificate_and_store(params):
        certificate = decode_string(params['certificate'])
        ret = libTO.TO_verify_ca_certificate_and_store(
            params['ca_key_index'], params['subca_key_index'],
            c_char_p(certificate), len(certificate))
        return {'status': hex(ret)[2:]}

    @register('VERIFY_CHAIN_CERTIFICATE_AND_STORE',
            in_params={'ca_key_index':'uint8', 'chain_cert': 'hex'},
            labels={'category': 'Authentication'})
    def TO_helper_verify_chain_certificate_and_store(params):
        chain_cert = decode_string(params['chain_cert'])
        ret = libTO.TO_helper_verify_chain_certificate_and_store(
                params['ca_key_index'], c_char_p(chain_cert), len(chain_cert))
        if ret == 0:
            ret = 0x90
        return {'status': hex(ret)[2:]}

    @register('GET_CHALLENGE_AND_STORE',
            out_params={'challenge': 'hex'},
            labels={'category': 'Authentication'})
    def TO_get_challenge_and_store():
        challenge_length = 32
        cc = c_int(challenge_length)
        challenge = b' ' * challenge_length
        ret = libTO.TO_get_challenge_and_store(c_char_p(challenge),
                byref(cc))
        return {'status': hex(ret)[2:],
                'challenge': encode_hex(challenge[:cc.value])}

    @register('VERIFY_CHALLENGE_SIGNATURE',
            in_params={'signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_verify_challenge_signature(params):
        signature = decode_string(params['signature'])
        ret = libTO.TO_verify_challenge_signature(c_char_p(signature),
                len(signature))
        return {'status': hex(ret)[2:]}

if not DISABLE_SIGNING:
    @register('SIGN',
            in_params={'key_index': 'uint8', 'challenge': 'hex'},
            out_params={'signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_sign(params):
        signature = b' ' * 64 # signature is 64 bytes
        challenge = decode_string(params['challenge'])
        ret = libTO.TO_sign(params['key_index'], c_char_p(challenge),
                len(challenge), c_char_p(signature))
        return {'status': hex(ret)[2:], 'signature': encode_hex(signature)}

    @register('VERIFY',
            in_params={'key_index': 'uint8', 'data': 'hex', 'signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_verify(params):
        data = decode_string(params['data'])
        signature = decode_string(params['signature'])
        ret = libTO.TO_verify(params['key_index'], c_char_p(data),
                len(data), c_char_p(signature))
        return {'status': hex(ret)[2:]}

    @register('SIGN_HASH',
            in_params={'key_index': 'uint8', 'hash': 'hex'},
            out_params={'signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_sign_hash(params):
        signature = b' ' * 64 # signature is 64 bytes
        digest_hash = decode_string(params['hash'])
        ret = libTO.TO_sign_hash(params['key_index'],
                c_char_p(digest_hash), c_char_p(signature))
        return {'status': hex(ret)[2:], 'signature': encode_hex(signature)}

    @register('VERIFY_HASH_SIGNATURE',
            in_params={'key_index': 'uint8', 'hash': 'hex', 'signature': 'hex'},
            labels={'category': 'Authentication'})
    def TO_verify_hash_signature(params):
        digest_hash = decode_string(params['hash'])
        signature = decode_string(params['signature'])
        ret = libTO.TO_verify_hash_signature(params['key_index'],
                c_char_p(digest_hash), c_char_p(signature))
        return {'status': hex(ret)[2:]}

if not DISABLE_TLS:
    @register('GET_TLS_RANDOM_AND_STORE',
            in_params={'timestamp': 'hex'},
            out_params={'random': 'hex'},
            labels={'category': 'TLS'})
    def TO_get_tls_random_and_store(params):
        timestamp = decode_string(params['timestamp'])
        random = b' ' * (TLS_RANDOM_SIZE)
        ret = libTO.TO_get_tls_random_and_store(c_char_p(timestamp),
                c_char_p(random))
        return {'status': hex(ret)[2:],
                'random': encode_hex(random)}

    @register('GET_TLS_MASTER_SECRET',
            out_params={'master_secret': 'hex'},
            labels={'category': 'TLS'})
    def TO_get_tls_master_secret():
        master_secret = b' ' * (TLS_MASTER_SECRET_SIZE)
        ret = libTO.TO_get_tls_master_secret(c_char_p(master_secret))
        return {'status': hex(ret)[2:],
                'master_secret': encode_hex(master_secret)}

    @register('RENEW_TLS_KEYS',
            in_params={'server_random': 'hex'},
            labels={'category': 'TLS'})
    def TO_renew_tls_keys(params):
        server_random = decode_string(params['server_random'])
        ret = libTO.TO_renew_tls_keys(c_char_p(server_random))
        return {'status': hex(ret)[2:]}

if not DISABLE_KEYS_MGMT:
    @register('SET_REMOTE_PUBLIC_KEY',
            in_params={'key_index': 'uint8', 'public_key': 'hex',
                'signature': 'hex'},
            labels={'category': 'Keys'})
    def TO_set_remote_public_key(params):
        public_key = decode_string(params['public_key'])
        signature = decode_string(params['signature'])
        ret = libTO.TO_set_remote_public_key(params['key_index'],
                c_char_p(public_key), c_char_p(signature))
        return {'status': hex(ret)[2:]}

    @register('RENEW_ECC_KEYS',
            in_params={'key_index': 'uint8'},
            labels={'category': 'Keys'})
    def TO_renew_ecc_keys(params):
        ret = libTO.TO_renew_ecc_keys(params['key_index'])
        return {'status': hex(ret)[2:]}

    @register('GET_PUBLIC_KEY',
            in_params={'key_index': 'uint8'},
            out_params={'public_key': 'hex', 'signature': 'hex'},
            labels={'category': 'Keys'})
    def TO_get_public_key(params):
        public_key = b' ' * 64
        signature = b' ' * 64
        ret = libTO.TO_get_public_key(params['key_index'],
                c_char_p(public_key), c_char_p(signature))
        return {'status': hex(ret)[2:], 'public_key': encode_hex(public_key),
                'signature': encode_hex(signature)}

    @register('GET_UNSIGNED_PUBLIC_KEY',
            in_params={'key_index': 'uint8'},
            out_params={'public_key': 'hex'},
            labels={'category': 'Keys'})
    def TO_get_unsigned_public_key(params):
        public_key = b' ' * 64
        ret = libTO.TO_get_unsigned_public_key(params['key_index'],
                c_char_p(public_key))
        return {'status': hex(ret)[2:], 'public_key': encode_hex(public_key)}

    @register('RENEW_SHARED_KEYS',
            in_params={'key_index': 'uint8', 'public_key_index': 'uint8'},
            labels={'category': 'Keys'})
    def TO_renew_shared_keys(params):
        ret = libTO.TO_renew_shared_keys(params['key_index'],
                params['public_key_index'])
        return {'status': hex(ret)[2:]}

if not DISABLE_FINGERPRINT:
    @register('GET_KEY_FINGERPRINT',
            in_params={'key_type': 'uint8',
                'key_index': 'uint8'},
            out_params={'fingerprint': 'hex'},
            labels={'category': 'Keys'})
    def TO_get_key_fingerprint(params):
        fingerprint = b' ' * KEY_FINGERPRINT_SIZE
        ret = libTO.TO_get_key_fingerprint(params['key_type'],
                params['key_index'], c_char_p(fingerprint))
        return {'status': hex(ret)[2:], 'fingerprint': encode_hex(fingerprint)}

if not DISABLE_HMAC:
    @register('COMPUTE_HMAC',
            in_params={'key_index': 'uint8', 'data': 'hex'},
            out_params={'hmac': 'hex'},
            labels={'category': 'MAC'})
    def TO_compute_hmac(params):
        hmac = b' ' * HMAC_SIZE
        data = decode_string(params['data'])
        ret = libTO.TO_compute_hmac(params['key_index'], c_char_p(data),
                len(data), c_char_p(hmac))
        return {'status': hex(ret)[2:], 'hmac': encode_hex(hmac)}

    @register('COMPUTE_HMAC_INIT',
            in_params={'key_index': 'uint8'},
            labels={'category': 'MAC'})
    def TO_compute_hmac_init(params):
        ret = libTO.TO_compute_hmac_init(params['key_index'])
        return {'status': hex(ret)[2:]}

    @register('COMPUTE_HMAC_UPDATE',
            in_params={'data': 'hex'},
            labels={'category': 'MAC'})
    def TO_compute_hmac_update(params):
        data = decode_string(params['data'])
        ret = libTO.TO_compute_hmac_update(c_char_p(data), len(data))
        return {'status': hex(ret)[2:]}

    @register('COMPUTE_HMAC_FINAL',
            out_params={'hmac': 'hex'},
            labels={'category': 'MAC'})
    def TO_compute_hmac_final(params):
        hmac = b' ' * HMAC_SIZE
        ret = libTO.TO_compute_hmac_final(c_char_p(hmac))
        return {'status': hex(ret)[2:], 'hmac': encode_hex(hmac)}

    @register('VERIFY_HMAC',
            in_params={'key_index': 'uint8', 'data': 'hex', 'hmac': 'hex'},
            labels={'category': 'MAC'})
    def TO_verify_hmac(params):
        data = decode_string(params['data'])
        hmac = decode_string(params['hmac'])
        ret = libTO.TO_verify_hmac(params['key_index'], c_char_p(data),
                len(data), c_char_p(hmac))
        return {'status': hex(ret)[2:]}

    @register('VERIFY_HMAC_INIT',
            in_params={'key_index': 'uint8'},
            labels={'category': 'MAC'})
    def TO_verify_hmac_init(params):
        ret = libTO.TO_verify_hmac_init(params['key_index'])
        return {'status': hex(ret)[2:]}

    @register('VERIFY_HMAC_UPDATE',
            in_params={'data': 'hex'},
            labels={'category': 'MAC'})
    def TO_verify_hmac_update(params):
        data = decode_string(params['data'])
        ret = libTO.TO_verify_hmac_update(c_char_p(data), len(data))
        print(ret)
        return {'status': hex(ret)[2:]}

    @register('VERIFY_HMAC_FINAL',
            in_params={'hmac': 'hex'},
            labels={'category': 'MAC'})
    def TO_verify_hmac_final(params):
        hmac = decode_string(params['hmac'])
        ret = libTO.TO_verify_hmac_final(c_char_p(hmac))
        return {'status': hex(ret)[2:]}

if not DISABLE_CMAC:
    @register('COMPUTE_CMAC',
            in_params={'key_index': 'uint8', 'data': 'hex'},
            out_params={'cmac': 'hex'},
            labels={'category': 'MAC'})
    def TO_compute_cmac(params):
        cmac = b' ' * CMAC_SIZE
        data = decode_string(params['data'])
        ret = libTO.TO_compute_cmac(params['key_index'], c_char_p(data),
                len(data), c_char_p(cmac))
        return {'status': hex(ret)[2:], 'cmac': encode_hex(cmac)}

    @register('VERIFY_CMAC',
            in_params={'key_index': 'uint8', 'data': 'hex', 'cmac': 'hex'},
            labels={'category': 'MAC'})
    def TO_verify_cmac(params):
        data = decode_string(params['data'])
        cmac = decode_string(params['cmac'])
        ret = libTO.TO_verify_cmac(params['key_index'], c_char_p(data),
                len(data), c_char_p(cmac))
        return {'status': hex(ret)[2:]}

if not DISABLE_AES_ENCRYPT:
    @register('ENCRYPT',
            in_params={'key_index': 'uint8', 'data': 'hex'},
            out_params={'initial_vector': 'hex', 'cryptogram': 'hex'},
            labels={'category': 'Messaging'})
    def TO_aes_encrypt(params):
        data = decode_string(params['data'])
        iv = b' ' * IV_SIZE
        crypto = b' ' * (len(data) + IV_SIZE)
        ret = libTO.TO_aes_encrypt(params['key_index'], c_char_p(data),
                len(data), c_char_p(iv), c_char_p(crypto))
        return {'status': hex(ret)[2:], 'initial_vector': encode_hex(iv),
                'cryptogram': encode_hex(crypto[:len(data)])}

    @register('IV_ENCRYPT',
            in_params={'key_index': 'uint8',
                'initial_vector': 'hex', 'data': 'hex'},
            out_params={'cryptogram': 'hex'},
            labels={'category': 'Messaging'})
    def TO_aes_iv_encrypt(params):
        data = decode_string(params['data'])
        iv = decode_string(params['initial_vector'])
        crypto = b' ' * len(data)
        ret = libTO.TO_aes_iv_encrypt(params['key_index'], c_char_p(iv),
                c_char_p(data), len(data), c_char_p(crypto))
        return {'status': hex(ret)[2:],
                'cryptogram': encode_hex(crypto)}

    @register('DECRYPT',
            in_params={'key_index': 'uint8', 'initial_vector': 'hex',
                'cryptogram': 'hex'},
            out_params={'data': 'hex'},
            labels={'category': 'Messaging'})
    def TO_aes_decrypt(params):
        crypto = decode_string(params['cryptogram'])
        iv = decode_string(params['initial_vector'])
        data = b' ' * len(crypto)
        ret = libTO.TO_aes_decrypt(params['key_index'], c_char_p(iv),
                c_char_p(crypto), len(crypto), c_char_p(data))
        return {'status': hex(ret)[2:],
                'data': encode_hex(data[:len(crypto)])}

if not DISABLE_SEC_MSG:
    @register('SECURE_MESSAGE',
            in_params={'aes_key_index': 'uint8', 'hmac_key_index': 'uint8',
                'data': 'hex'},
            out_params={'initial_vector': 'hex', 'cryptogram': 'hex',
                'hmac': 'hex'},
            labels={'category': 'Messaging'})
    def TO_secure_message(params):
        data = decode_string(params['data'])
        iv = b' ' * IV_SIZE # initial vector
        cryptogram = b' ' * len(data)
        hmac = b' ' * HMAC_SIZE
        ret = libTO.TO_secure_message(params['aes_key_index'],
                params['hmac_key_index'], c_char_p(data), len(data),
                c_char_p(iv), c_char_p(cryptogram), c_char_p(hmac))
        return {'status': hex(ret)[2:],
                'initial_vector': encode_hex(iv),
                'cryptogram': encode_hex(cryptogram),
                'hmac': encode_hex(hmac)}

    @register('UNSECURE_MESSAGE',
            in_params={'aes_key_index': 'uint8',
                'hmac_key_index': 'uint8', 'initial_vector': 'hex',
                'cryptogram': 'hex', 'hmac': 'hex'},
            out_params={'data': 'hex'},
            labels={'category': 'Messaging'})
    def TO_unsecure_message(params):
        iv = decode_string(params['initial_vector'])
        cryptogram = decode_string(params['message'])
        hmac = decode_string(params['hmac'])
        data = b' ' * len(cryptogram)
        ret = libTO.TO_unsecure_message(params['aes_key_index'],
                params['hmac_key_index'], c_char_p(iv), c_char_p(cryptogram),
                len(cryptogram), c_char_p(hmac), c_char_p(data))
        return {'status': hex(ret)[2:],
                'data': encode_hex(data)}

if not DISABLE_NVM:
    @register('WRITE_NVM',
            in_params={'offset': 'uint16', 'data': 'hex', 'key': 'hex'},
            labels={'category': 'NVM'})
    def TO_write_nvm(params):
        offset = params['offset']
        data = decode_string(params['data'])
        length = len(data)
        key = decode_string(params['key'])
        ret = libTO.TO_write_nvm(offset, c_char_p(data), length,
                c_char_p(key))
        return {'status': hex(ret)[2:]}

    @register('READ_NVM',
            in_params={'offset': 'uint16', 'length': 'uint16', 'key': 'hex'},
            labels={'category': 'NVM'})
    def TO_read_nvm(params):
        offset = params['offset']
        length = params['length']
        data = b' ' * length
        key = decode_string(params['key'])
        ret = libTO.TO_read_nvm(offset, c_char_p(data), length,
                c_char_p(key))
        return {'status': hex(ret)[2:], 'data': encode_hex(data)}

    @register('GET_NVM_SIZE',
            out_params={'size': 'uint16'},
            labels={'category': 'NVM'})
    def TO_get_nvm_size():
        size = c_int()
        ret = libTO.TO_get_nvm_size(byref(size))
        return {'status': hex(ret)[2:], 'size': size.value}

