#!/usr/bin/env python3

"""
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

Copyright 2016 Trusted Objects

@brief       Secure Element shell
@author      Trusted-Objects
"""

import cmd, sys
from binascii import Error as binasciiError
from TO.methods import methods, load_library
from shlex import split as split_args
from TO.const import TOCERTF_X509, TOCERTF_STANDALONE, TOCERTF_SHORT_V2
from TO.seclink import setkeys as seclink_setkeys, getkeys as seclink_getkeys, \
        resetkeys as seclink_resetkeys
from TO.config import VERSION

def TO_session(func):
    """ Secure Element session decorator, applied on shell commands, and
    responsible of I2C device initialization and finalization
    """
    def wrapper(self, *args, **kwargs):
        wrapper_ret = 0
        ret = 0
        if (not self.persistent_session):
            ret = methods['TO_INIT']['func']()
        if ret != 0:
            print("Error: failed to initialize SE communication, " \
                    "error %d" % ret)
            wrapper_ret = 1
        else:
            try:
                ret = func(self, *args, **kwargs)
                if ret != '90':
                    print("Error: failed to run command, code=%s" % ret)
                    wrapper_ret = 1
            except (IndexError, ValueError, binasciiError):
                print("Error: bad command arguments")
                wrapper_ret = 1
            except (KeyError, AttributeError):
                print("Unsupported command")
                wrapper_ret = 1
            if (not self.persistent_session):
                ret = methods['TO_FINI']['func']()
                if ret != 0:
                    print("Warning: failed to finalize SE communication, " \
                            "error %d" % ret)
        if self.ret_cmd_errors:
            return wrapper_ret
        else:
            return 0
    return wrapper

class TOShell(cmd.Cmd):
    intro = 'Welcome to the Trusted Objects Secure Element shell, ' \
            'version ' + VERSION + '.\n' \
            'Type help or ? to list commands.'
    prompt = 'Secure Element % '
    ret_cmd_errors = True
    persistent_session = False

    def preloop(self):
        """ Errors are not returned by commands in loop mode because it may
        break shell loop
        """
        self.ret_cmd_errors = False

    def can_exit(self):
        return True
    def onecmd(self, line):
        r = super (TOShell, self).onecmd(line)
        if r and self.can_exit():
            return True
        return False

    def help_exit(self):
        print('Exit the shell')
    def do_exit(self, s):
        if self.persistent_session:
            ret = methods['TO_FINI']['func']()
        return True
    help_EOF= help_exit
    do_EOF = do_exit

    def help__configure(self):
        print('Configure I2C bus' \
                '\nUsage: configure <i2c_addr>' \
                '\nNote: I2C address is 7-bits length (MSB=0)')
    def do__configure(self, args):
        retval = 0
        args_l = split_args(args)
        i2c_addr = args_l[0]
        ret = methods['TO_CONFIG']['func'](i2c_addr, "0")
        if ret != 0:
            print("Unable to configure I2C bus, error %X" % ret)
            retval = 1
        else:
            print("OK")
        if self.ret_cmd_errors:
            return retval
        else:
            return 0

    def help__session_begin(self):
        print('Begin I2C session' \
                '(normally, a session is create for each command)');
    def do__session_begin(self, args):
        ret = methods['TO_INIT']['func']()
        if ret != 0:
            print("Error: failed to initialize SE communication, " \
                    "error %d" % ret)
            if self.ret_cmd_errors:
                return 1
            else:
                return 0
        self.persistent_session = True
        return 0

    def help__session_finish(self):
        print('Finish I2C session' \
                '(normally, a session is create for each command)');
    def do__session_finish(self, args):
        ret = methods['TO_FINI']['func']()
        if ret != 0:
            print("Error: failed to finalize SE communication, " \
                    "error %d" % ret)
            if self.ret_cmd_errors:
                return 1
            else:
                return 0
        self.persistent_session = False
        return 0

    def help__seclink_bypass(self):
        print('Bypass Secure Element secure link, if enabled and allowed' \
                '\nUsage: seclink_bypass [1/0] (default 1 if no value given)')
    def do__seclink_bypass(self, args):
        args_l = split_args(args)
        if (len(args_l) != 1):
            bypass = 1
        else:
            bypass = int(args_l[0])
        methods['TO_SECLINK_BYPASS']['func'](bypass)
        print("OK")
        return 0

    def help__seclink_set_keys(self):
        print('Set secure link keys (concatenated)')
    def do__seclink_set_keys(self, args):
        args_l = split_args(args)
        if (len(args_l) != 1):
            print("Missing or bad keys argument")
            if self.ret_cmd_errors:
                return 1
            else:
                return 0
        if seclink_setkeys(args_l[0]) != 0:
            print("Error setting seclink keys")
            if self.ret_cmd_errors:
                return 1
        return 0

    def help__seclink_get_keys(self):
        print('Get secure link keys (concatenated)')
    def do__seclink_get_keys(self, args):
        print(str(seclink_getkeys(), 'ascii'))
        return 0

    def help__seclink_reset_keys(self):
        print('Reset secure link keys to default')
    def do__seclink_reset_keys(self, args):
        seclink_resetkeys()

    def help__last_command_duration(self):
        print('Return last successful command duration, in seconds (float)');
    def do__last_command_duration(self, args):
        # Init / fini calls are needed in order to connect to I2C net bridge if
        # net_bridge I2C wrapper is used
        if (not self.persistent_session):
            ret = methods['TO_INIT']['func']()
            if ret != 0:
                print("Error: INIT failed, error %d" % ret)
                if self.ret_cmd_errors:
                    return 1
                else:
                    return 0
        ret = methods['TO_LAST_COMMAND_DURATION']['func']()
        if (not self.persistent_session):
            methods['TO_FINI']['func']()
        if ret['status'] == '0':
            print("%f" % (int(ret['duration']) / 1000000))
        else:
            print("Error: %s" % ret)
            if self.ret_cmd_errors:
                return 1
        return 0

    def help_raw_cmd(self):
        print('Send raw Secure Element command and get raw response.' \
                '\nNote: headers are included in command and response.' \
                '\nUsage: raw_cmd <hex data> [expected response length]' \
                '\nNote: expected response length does not take response ' \
                'headers into account' \
                '\nNote: use quotes around arguments containing spaces')
    def do_raw_cmd(self, args):
        retval = 0
        respbytes = None
        args_l = split_args(args)
        command = args_l[0]
        command = command.replace('\r', '').replace('\n', '').replace(' ', '')
        try:
            resp_len = 4 + int(args_l[1])
        except IndexError:
            resp_len = 4
        try:
            if (not self.persistent_session):
                ret = methods['TO_INIT']['func']()
                if ret != 0:
                    raise Exception("Unable to initialize Secure Element " \
                            "communication for raw command, error %X" % ret)
            ret = methods['TO_WRITE']['func'](command)
            if ret != 0:
                print("Unable to send command, error %X" % ret)
            ret, respbytes = methods['TO_READ']['func'](resp_len)
            if ret != 0:
                raise Exception("Unable to recieve response, error %X" % ret)
        except Exception as e:
            print(e)
            retval = 1
        else:
            response = str(respbytes, 'ascii')
            print("%s" % response)
            if response[4] != '9' or response[5] != '0':
                retval = 1
        finally:
            if (not self.persistent_session):
                ret = methods['TO_FINI']['func']()
                if ret != 0:
                    print("Warning: unable to finalize Secure Element " \
                            "communication after raw command, error %X" % ret)
            if self.ret_cmd_errors:
                return retval
            else:
                return 0

    def help_get_sn(self):
        print('Returns the unique Secure Element Serial Number')
    @TO_session
    def do_get_sn(self, args):
        func = methods['GET_SN']['func']
        ret = func()
        if ret['status'] == '90':
            print('%s' % str(ret['serial_number'], 'ascii'))
        return ret['status']

    def help_get_pn(self):
        print('Returns the Product Number of the TO')
    @TO_session
    def do_get_pn(self, args):
        func = methods['GET_PN']['func']
        ret = func()
        if ret['status'] == '90':
            print('%s' % ret['product_number'])
        return ret['status']

    def help_get_hw_version(self):
        print('Returns the Hardware Version of the TO')
    @TO_session
    def do_get_hw_version(self, args):
        func = methods['GET_HW_VERSION']['func']
        ret = func()
        if ret['status'] == '90':
            print('%s' % str(ret['hardware_version'], 'ascii'))
        return ret['status']

    def help_get_sw_version(self):
        print('Returns the Software Version of the TO')
    @TO_session
    def do_get_sw_version(self, args):
        func = methods['GET_SW_VERSION']['func']
        ret = func()
        if ret['status'] == '90':
            print('major = %d\nminor = %d\nrev = %d' % \
                    (ret['major'], ret['minor'], ret['revision']))
        return ret['status']

    def help_get_random(self):
        print('Returns a random number of the given length' \
                '\nUsage: get_random <length>')
    @TO_session
    def do_get_random(self, args):
        args_l = args.split()
        params = {'random_length': int(args_l[0])}
        func = methods['GET_RANDOM']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['random'], 'ascii'))
        return ret['status']

    def help_get_status_PIO_config(self):
        print('Returns the status PIO config')
    @TO_session
    def do_get_status_PIO_config(self, args):
        func = methods['GET_STATUS_PIO_CONFIG']['func']
        ret = func()
        if ret['status'] == '90':
            if ret['enable']:
                print("enabled")
                if ret['opendrain']:
                    print("open drain")
                else:
                    print("push pull")
                if ret['ready_level']:
                    print("ready level high")
                else:
                    print("ready level low")
                if ret['idle_hz']:
                    print("idle high impedance")
            else:
                print("disabled")
        return ret['status']

    def help_set_status_PIO_config(self):
        print('Set the status PIO config' \
                '\nUsage: set_status_PIO_config ' \
                '<enable> <open drain> <ready level> <idle high impedance>' \
                '\n\t(expected values are 1 or 0)')
    @TO_session
    def do_set_status_PIO_config(self, args):
        args_l = args.split()
        params = {'enable': int(args_l[0]),
                'opendrain': int(args_l[1]), 'ready_level': int(args_l[2]),
                'idle_hz': int(args_l[3])}
        func = methods['SET_STATUS_PIO_CONFIG']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_sha256(self):
        print('Returns the SHA256 hash of the given data' \
                '\nUsage: sha256 <hex data>')
    @TO_session
    def do_sha256(self, args):
        args_l = args.split()
        params = {'data': args_l[0]}
        func = methods['SHA256']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['sha256'], 'ascii'))
        return ret['status']

    def help_sha256_init(self):
        print('Initialize SHA256 hash computation' \
                '\nTo use before sha256_update and sha256_final' \
                '\nUsage: sha256_init')
    @TO_session
    def do_sha256_init(self, args):
        func = methods['SHA256_INIT']['func']
        ret = func()
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_sha256_update(self):
        print('Updates SHA256 hash computation with the given data' \
                '\nTo use after sha256_init and before sha256_final,' \
                'can be called several times' \
                '\nUsage: sha256_update <hex data>')
    @TO_session
    def do_sha256_update(self, args):
        args_l = args.split()
        params = {'data': args_l[0]}
        func = methods['SHA256_UPDATE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_sha256_final(self):
        print('Returns the SHA256 hash of the data previously given' \
                '\nTo use after sha256_init and sha256_update' \
                '\nUsage: sha256_final')
    @TO_session
    def do_sha256_final(self, args):
        func = methods['SHA256_FINAL']['func']
        ret = func()
        if ret['status'] == '90':
            print('%s' % str(ret['sha256'], 'ascii'))
        return ret['status']

    def help_get_certificate_subject_cn(self):
        print('Returns subject common name of one of the SE certificates' \
                '\nUsage: get_certificate_subject_cn <index>')
    @TO_session
    def do_get_certificate_subject_cn(self, args):
        args_l = args.split()
        params = {'index': int(args_l[0])}
        func = methods['GET_CERTIFICATE_SUBJECT_CN']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['subject_cn'], 'ascii'))
        return ret['status']

    def help_get_certificate(self):
        print('Returns one of the Secure Element certificates' \
                '\nUsage: get_certificate <index>')
    @TO_session
    def do_get_certificate(self, args):
        args_l = args.split()
        params = {'index': int(args_l[0])}
        func = methods['GET_CERTIFICATE']['func']
        ret = func(params)
        if ret['status'] == '90':
            for k, v in ret.items():
                if k == 'status':
                    continue
                print('%s = %s' % (k, str(v, 'ascii')))
        return ret['status']

    def help_get_certificate_x509(self):
        print('Returns one of the Secure Element x509 DER certificates' \
                '\nUsage: get_certificate_x509 <index>')
    @TO_session
    def do_get_certificate_x509(self, args):
        args_l = args.split()
        params = {'index': int(args_l[0])}
        func = methods['GET_CERTIFICATE_X509']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % (str(ret['cert'], 'ascii')))
        return ret['status']

    def help_get_certificate_and_sign(self):
        print('Returns one of the Secure Element certificate and the signature '
                'of a challenge made with its private key' \
                '\nUsage: get_certificate_and_sign <index> <hex challenge>')
    @TO_session
    def do_get_certificate_and_sign(self, args):
        args_l = args.split()
        params = {'index': int(args_l[0]), 'challenge': args_l[1]}
        func = methods['GET_CERTIFICATE_AND_SIGN']['func']
        ret = func(params)
        if ret['status'] == '90':
            for k, v in ret.items():
                if k == 'status':
                    continue
                print('%s = %s' % (k, str(v, 'ascii')))
        return ret['status']

    def help_get_certificate_x509_and_sign(self):
        print('Returns one of the Secure Element x509 DER certificate and the '
                'signature of a challenge made with its private key' \
                '\nUsage: get_certificate_x509_and_sign <index> <hex challenge>')
    @TO_session
    def do_get_certificate_x509_and_sign(self, args):
        args_l = args.split()
        params = {'index': int(args_l[0]), 'challenge': args_l[1]}
        func = methods['GET_CERTIFICATE_X509_AND_SIGN']['func']
        ret = func(params)
        if ret['status'] == '90':
                print('cert = %s\nchallenge signature = %s'
                        % (str(ret['cert'], 'ascii'),
                            str(ret['signature'], 'ascii')))
        return ret['status']

    def help_sign(self):
        print('Returns the Elliptic Curve Digital Signature of the given data' \
                '\nUsage: sign <key index> <hex challenge>')
    @TO_session
    def do_sign(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'challenge': args_l[1]}
        func = methods['SIGN']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['signature'], 'ascii'))
        return ret['status']

    def help_verify(self):
        print('Verifies the given Elliptic Curve Digital Signature of the' \
                ' given data' \
                '\nUsage: verify <key index> <hex challenge> <hex signature>')
    @TO_session
    def do_verify(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'data': args_l[1],
                'signature': args_l[2]}
        func = methods['VERIFY']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_sign_hash(self):
        print('Returns the Elliptic Curve Digital Signature of the given hash' \
                '\nUsage: sign <key index> <hex hash>')
    @TO_session
    def do_sign_hash(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'hash': args_l[1]}
        func = methods['SIGN_HASH']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['signature'], 'ascii'))
        return ret['status']

    def help_verify_hash_signature(self):
        print('Verifies the given Elliptic Curve Digital Signature of the' \
                ' given hash' \
                '\nUsage: verify <key index> <hex hash> <hex signature>')
    @TO_session
    def do_verify_hash_signature(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'hash': args_l[1],
                'signature': args_l[2]}
        func = methods['VERIFY_HASH_SIGNATURE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_verify_certificate_and_store(self):
        print('Requests to verify Certificate Authority Signature of the' \
                ' given certificate' \
                '\nUsage with x509 certificate: ' \
                'verify_certificate_and_store <ca key index> %d <cert bytes>' \
                '\nUsage with standalone certificate: ' \
                'verify_certificate_and_store <ca key index> %d <cert ca id>' \
                '<cert serial> <cert key> <cert signature>' \
                '\nUsage with short v2 certificate: ' \
                'verify_certificate_and_store <ca key index> %d <cert ca id> ' \
                '<cert serial> <cert date> <cert subject name> <cert key> ' \
                '<cert signature>'
                % (TOCERTF_X509, TOCERTF_STANDALONE, TOCERTF_SHORT_V2))
    @TO_session
    def do_verify_certificate_and_store(self, args):
        args_l = args.split()
        ca_key_index = int(args_l[0])
        cert_format = int(args_l[1])
        if cert_format is TOCERTF_STANDALONE:
            cert_raw = args_l[2] # CA ID
            cert_raw += args_l[3] # serial
            cert_raw += args_l[4] # public key
            cert_raw += args_l[5] # signature
        elif cert_format is TOCERTF_SHORT_V2:
            cert_raw = args_l[2] # CA ID
            cert_raw += args_l[3] # serial
            cert_raw += args_l[4] # date
            cert_raw += args_l[5] # subject name
            cert_raw += args_l[6] # public key
            cert_raw += args_l[7] # signature
        elif cert_format is TOCERTF_X509:
            cert_raw = args_l[2]
        else:
            raise ValueError
        params = {'ca_key_index': ca_key_index,
                'format': cert_format, 'cert_raw': cert_raw}
        func = methods['VERIFY_CERTIFICATE_AND_STORE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_verify_ca_certificate_and_store(self):
        print('Requests to verify Certificate Authority Signature of the' \
                ' given subCA certificate' \
                '\nUsage: ' \
                'verify_ca_certificate_and_store <ca key index> <subca_key_index> ' \
                '<cert bytes>')
    @TO_session
    def do_verify_ca_certificate_and_store(self, args):
        args_l = args.split()
        ca_key_index = int(args_l[0])
        subca_key_index = int(args_l[1])
        certificate = args_l[2]
        params = {'ca_key_index': ca_key_index,
                'subca_key_index': subca_key_index,
                'certificate': certificate}
        func = methods['VERIFY_CA_CERTIFICATE_AND_STORE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_get_challenge_and_store(self):
        print('Returns a challenge and store it into Secure Element memory')
    @TO_session
    def do_get_challenge_and_store(self, args):
        func = methods['GET_CHALLENGE_AND_STORE']['func']
        ret = func()
        if ret['status'] == '90':
            print('%s' % str(ret['challenge'], 'ascii'))
        return ret['status']

    def help_verify_challenge_signature(self):
        print('Verifies if the given signature matches with the signature of' \
                ' the challenge previously sent by `get_challenge_and_store`' \
                ', using the public key of the certificate previously sent' \
                ' by VERIFY_CERTIFICATE_AND_STORE (standalone certificate)' \
                '\nUsage: verify_challenge_signature <hex signature>')
    @TO_session
    def do_verify_challenge_signature(self, args):
        args_l = args.split()
        params = {'signature': args_l[0]}
        func = methods['VERIFY_CHALLENGE_SIGNATURE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_verify_chain_certificate_and_store(self):
        print('Requests to verify given Certificate chain' \
                '\nUsage: ' \
                'verify_chain_certificate_and_store <ca_key_index (255: auto)> '
                '<cert bytes>')
    @TO_session
    def do_verify_chain_certificate_and_store(self, args):
        args_l = args.split()
        ca_key_index = int(args_l[0])
        chain_cert = args_l[1]
        params = {'ca_key_index': ca_key_index, 'chain_cert': chain_cert}
        func = methods['VERIFY_CHAIN_CERTIFICATE_AND_STORE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_get_tls_random_and_store(self):
        print('Returns a TLS random and store it into Secure Element memory,' \
                ' the challenge is concatenated with the given timestamp' \
                '\nUsage: get_tls_random_and_store <hex timestamp>')
    @TO_session
    def do_get_tls_random_and_store(self, args):
        args_l = args.split()
        params = {'timestamp': args_l[0]}
        func = methods['GET_TLS_RANDOM_AND_STORE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['random'], 'ascii'))
        return ret['status']

    def help_set_remote_public_key(self):
        print('Requests the Secure Element to store, at the given index, ' \
                'a public key to be used in the ECIES process.' \
                '\nUsage: set_remote_public_key <key index> <hex public key>' \
                ' <hex signature>')
    @TO_session
    def do_set_remote_public_key(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'public_key': args_l[1],
                'signature': args_l[2]}
        func = methods['SET_REMOTE_PUBLIC_KEY']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_renew_ecc_keys(self):
        print('Renews Elliptic Curve key pair for the corresponding index' \
                '\nUsage: renew_ecc_keys <key index>')
    @TO_session
    def do_renew_ecc_keys(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0])}
        func = methods['RENEW_ECC_KEYS']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_get_public_key(self):
        print('Returns the public keys corresponding to the given index, and' \
                ' the signature of this public key' \
                '\nUsage: get_public_key <key index>')
    @TO_session
    def do_get_public_key(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0])}
        func = methods['GET_PUBLIC_KEY']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('public key = %s\nsignature = %s' %
                    (str(ret['public_key'], 'ascii'),
                        str(ret['signature'], 'ascii')))
        return ret['status']

    def help_get_unsigned_public_key(self):
        print('Returns the public keys corresponding to the given index' \
                '\nUsage: get_unsigned_public_key <key index>')
    @TO_session
    def do_get_unsigned_public_key(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0])}
        func = methods['GET_UNSIGNED_PUBLIC_KEY']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('public key = %s' % (str(ret['public_key'], 'ascii')))
        return ret['status']

    def help_renew_shared_keys(self):
        print('Renews shared keys (AES and HMAC) for the corresponding index' \
                '\nUsage: renew_shared_keys <key index> <public key index>')
    @TO_session
    def do_renew_shared_keys(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]),
                'public_key_index': int(args_l[1])}
        func = methods['RENEW_SHARED_KEYS']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_get_tls_master_secret(self):
        print('Returns TLS master secret.' \
                '\nUsage: get_tls_master_secret')
    @TO_session
    def do_get_tls_master_secret(self, args):
        args_l = args.split()
        func = methods['GET_TLS_MASTER_SECRET']['func']
        ret = func()
        if ret['status'] == '90':
            print('%s' % str(ret['master_secret'], 'ascii'))
        return ret['status']

    def help_renew_tls_keys(self):
        print('Derive TLS master secret.' \
                '\nUsage: renew_tls_keys <server random hex>')
    @TO_session
    def do_renew_tls_keys(self, args):
        args_l = args.split()
        params = {'server_random': args_l[0]}
        func = methods['RENEW_TLS_KEYS']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_get_key_fingerprint(self):
        print('Returns the fingerprint of the key corresponding to given ' \
                'type and index.' \
                '\nUsage: get_key_fingerprint <key type> <key index>\n' \
                'Key types:\n' \
                '\tKTYPE_CERT_KPUB = 0\n' \
                '\tKTYPE_CERT_KPRIV = 1\n' \
                '\tKTYPE_CA_KPUB = 2\n' \
                '\tKTYPE_REMOTE_KPUB = 3\n' \
                '\tKTYPE_ECIES_KPUB = 4\n' \
                '\tKTYPE_ECIES_KPRIV = 5\n' \
                '\tKTYPE_ECIES_KAES = 6\n' \
                '\tKTYPE_ECIES_KMAC = 7\n' \
                '\tKTYPE_LORA_KAPP = 8\n' \
                '\tKTYPE_LORA_KNET = 9\n' \
                '\tKTYPE_LORA_KSAPP = 10\n' \
                '\tKTYPE_LORA_KSNET = 11')
    @TO_session
    def do_get_key_fingerprint(self, args):
        args_l = args.split()
        params = {'key_type': int(args_l[0]), 'key_index': int(args_l[1])}
        func = methods['GET_KEY_FINGERPRINT']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['fingerprint'], 'ascii'))
        return ret['status']

    def help_compute_hmac(self):
        print('Computes a 256-bit HMAC tag based on SHA256 hash function' \
                '\nUsage: compute_hmac <key index> <hex data>')
    @TO_session
    def do_compute_hmac(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'data': args_l[1]}
        func = methods['COMPUTE_HMAC']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['hmac'], 'ascii'))
        return ret['status']

    def help_compute_hmac_init(self):
        print('Computes a 256-bit HMAC tag based on SHA256 hash function' \
                '\nTo use before compute_hmac_update and compute_hmac_final' \
                '\nUsage: compute_hmac_init <key index>')
    @TO_session
    def do_compute_hmac_init(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0])}
        func = methods['COMPUTE_HMAC_INIT']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_compute_hmac_update(self):
        print('Computes a 256-bit HMAC tag based on SHA256 hash function' \
                '\nTo use after compute_hmac_init and before ' \
                'compute_hmac_final to send data to compute HMAC on, can be ' \
                'called several times' \
                '\nUsage: compute_hmac_update <hex data>')
    @TO_session
    def do_compute_hmac_update(self, args):
        args_l = args.split()
        params = {'data': args_l[0]}
        func = methods['COMPUTE_HMAC_UPDATE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_compute_hmac_final(self):
        print('Computes a 256-bit HMAC tag based on SHA256 hash function' \
                '\nTo use after compute_hmac_init and compute_hmac_update' \
                '\nUsage: compute_hmac_final')
    @TO_session
    def do_compute_hmac_final(self, args):
        func = methods['COMPUTE_HMAC_FINAL']['func']
        ret = func(None)
        if ret['status'] == '90':
            print('%s' % str(ret['hmac'], 'ascii'))
        return ret['status']

    def help_verify_hmac(self):
        print('Verifies if the HMAC tag is correct for the given data' \
                '\nUsage: verify_hmac <key index> <hex data> <hex hmac>')
    @TO_session
    def do_verify_hmac(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'data': args_l[1],
                'hmac': args_l[2]}
        func = methods['VERIFY_HMAC']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_verify_hmac_init(self):
        print('Verifies if the HMAC tag is correct for the given data' \
                '\nTo use before verify_hmac_update and verify_hmac_final' \
                '\nUsage: verify_hmac_init <key index>')
    @TO_session
    def do_verify_hmac_init(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0])}
        func = methods['VERIFY_HMAC_INIT']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_verify_hmac_update(self):
        print('Verifies if the HMAC tag is correct for the given data' \
                '\nTo use after verify_hmac_init and before ' \
                'verify_hmac_final to send data to verify HMAC on, can be ' \
                'called several times' \
                '\nUsage: verify_hmac_update <hex data>')
    @TO_session
    def do_verify_hmac_update(self, args):
        args_l = args.split()
        params = {'data': args_l[0]}
        func = methods['VERIFY_HMAC_UPDATE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_verify_hmac_final(self):
        print('Verifies if the HMAC tag is correct for the given data' \
                '\nTo use after verify_hmac_init and verify_hmac_update' \
                '\nUsage: verify_hmac_final <hex hmac>')
    @TO_session
    def do_verify_hmac_final(self, args):
        args_l = args.split()
        params = {'hmac': args_l[0]}
        func = methods['VERIFY_HMAC_FINAL']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_compute_cmac(self):
        print('Computes a 128-bit CMAC tag based on AES128 algorithm' \
                '\nUsage: compute_cmac <key index> <hex data>')
    @TO_session
    def do_compute_cmac(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'data': args_l[1]}
        func = methods['COMPUTE_CMAC']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['cmac'], 'ascii'))
        return ret['status']

    def help_verify_cmac(self):
        print('Verifies if the CMAC tag is correct for the given data' \
                '\nUsage: verify_cmac <key index> <hex data> <hex cmac>')
    @TO_session
    def do_verify_cmac(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'data': args_l[1],
                'cmac': args_l[2]}
        func = methods['VERIFY_CMAC']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('OK')
        return ret['status']

    def help_aes_encrypt(self):
        print('Encrypts data using AES128 algorithm in CBC mode of operation' \
                ', and using the secret key corresponding to the given index' \
                '\nUsage: aes_encrypt <key index> <hex data (size multiple ' \
                'of 16)>')
    @TO_session
    def do_aes_encrypt(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'data': args_l[1]}
        func = methods['ENCRYPT']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('initial vector = %s\ncryptogram = %s' %
                    (str(ret['initial_vector'], 'ascii'),
                        str(ret['cryptogram'], 'ascii')))
        return ret['status']

    def help_aes_iv_encrypt(self):
        print('This command is similar to aes_encrypt command except that ' \
                'Initial Vector is given by user' \
                '\nUsage: aes_iv_encrypt <key index> <initial vector> ' \
                '<hex data (size multiple of 16)>')
    @TO_session
    def do_aes_iv_encrypt(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'initial_vector': args_l[1],
                'data': args_l[2]}
        func = methods['IV_ENCRYPT']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('cryptogram = %s' % str(ret['cryptogram'], 'ascii'))
        return ret['status']

    def help_aes_decrypt(self):
        print('Reverse of `aes_encrypt`' \
                '\nUsage: aes_decrypt <key index> <hex initial vector>' \
                ' <hex cryptogram>')
    @TO_session
    def do_aes_decrypt(self, args):
        args_l = args.split()
        params = {'key_index': int(args_l[0]), 'initial_vector': args_l[1],
                'cryptogram': args_l[2]}
        func = methods['DECRYPT']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['data'], 'ascii'))
        return ret['status']

    def help_secure_message(self):
        print('Transforms a message into a secured message containing a' \
                ' cryptogram and a HMAC tag.' \
                '\nUsage: secure_message <aes key index> <hmac key index>' \
                ' <hex data (size multiple of 16)>')
    @TO_session
    def do_secure_message(self, args):
        args_l = args.split()
        params = {'aes_key_index': int(args_l[0]),
                'hmac_key_index': int(args_l[1]), 'data': args_l[2]}
        func = methods['SECURE_MESSAGE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('initial vector = %s\ncryptogram = %s\nhmac = %s' %
                    (str(ret['initial_vector'], 'ascii'),
                        str(ret['cryptogram'], 'ascii'),
                        str(ret['hmac'], 'ascii')))
        return ret['status']

    def help_unsecure_message(self):
        print('Reverse of `secure_message`' \
                '\nUsage: unsecure_message <aes key index> <hmac key index>' \
                ' <hex initial vector> <hex cryptogram> <hex hmac>')
    @TO_session
    def do_unsecure_message(self, args):
        args_l = args.split()
        params = {'aes_key_index': int(args_l[0]),
            'hmac_key_index': int(args_l[1]),
            'initial_vector': args_l[2],
            'message': args_l[3],
            'hmac': args_l[4]}
        func = methods['UNSECURE_MESSAGE']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('%s' % str(ret['data'], 'ascii'))
        return ret['status']

    def help_write_nvm(self):
        print('Write data to client reserved NVM.' \
                '\nUsage: write_nvm <offset> <data> <aes key>')
    @TO_session
    def do_write_nvm(self, args):
        args_l = args.split()
        params = {'offset': int(args_l[0]), 'data': args_l[1],
                'key': args_l[2]}
        func = methods['WRITE_NVM']['func']
        ret = func(params)
        return ret['status']

    def help_read_nvm(self):
        print('Read data from client reserved NVM.' \
                '\nUsage: read_nvm <offset> <length> <aes key>')
    @TO_session
    def do_read_nvm(self, args):
        args_l = args.split()
        params = {'offset': int(args_l[0]), 'length': int(args_l[1]),
                'key': args_l[2]}
        func = methods['READ_NVM']['func']
        ret = func(params)
        if ret['status'] == '90':
            print('data:\n%s' % str(ret['data'], 'ascii'))
        return ret['status']

    def help_get_nvm_size(self):
        print('Returns the user NVM size')
    @TO_session
    def do_get_nvm_size(self, args):
        func = methods['GET_NVM_SIZE']['func']
        ret = func()
        if ret['status'] == '90':
            print('%d' % (ret['size']))
        return ret['status']

if __name__ == '__main__':
    load_library('TO', 'TO.TO_methods')
    if (len(sys.argv) > 1):
        command = ''
        for arg in sys.argv[1:]:
            command += arg + ' '
        ret = TOShell().onecmd(command)
    else:
        ret = TOShell().cmdloop()
    sys.exit(ret)
