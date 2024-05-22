#!/bin/bash

# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
# Copyright 2016 Trusted Objects
#
# @brief       Shell script to set Secure Element remote public key
# @author      Trusted-Objects

export LD_LIBRARY_PATH=/usr/local/lib

echo "CA key index?"
read CA_KEY_INDEX
echo "Cert format?"
read CERT_FORMAT
echo "Cert CA ID?"
read CERT_CA_ID
echo "Cert serial?"
read CERT_SERIAL
echo "Cert pubkey?"
read CERT_PUBKEY
echo "Cert signature?"
read CERT_SIGNATURE
TOsh.py verify_certificate_and_store $CA_KEY_INDEX $CERT_FORMAT \
        $CERT_CA_ID $CERT_SERIAL $CERT_PUBKEY $CERT_SIGNATURE
if [ $? -ne 0 ]
then
        echo "Unable to verify certificate and store"
        exit 1
fi

echo "Challenge:"
TOsh.py get_challenge_and_store
if [ $? -ne 0 ]
then
        echo "Unable to get challenge"
        exit 2
fi

echo "Challenge sha256 signature using cert privkey?"
read CHALLENGE_SIGN
TOsh.py verify_challenge_signature $CHALLENGE_SIGN
if [ $? -ne 0 ]
then
        echo "Unable to verify challenge signature"
        exit 3
fi

echo "Remote public key index?"
read REMOTE_PUBKEY_INDEX
echo "Remote public key?"
read REMOTE_PUBKEY
echo "Remote public key SHA256 signature using cert privkey?"
read REMOTE_PUBKEY_SIGNATURE
TOsh.py set_remote_public_key $REMOTE_PUBKEY_INDEX $REMOTE_PUBKEY \
        $REMOTE_PUBKEY_SIGNATURE
if [ $? -ne 0 ]
then
        echo "Unable to set remote public key"
        exit 3
fi

echo "Remote public key set successfully."

echo
echo "Renewing shared keys $REMOTE_PUBKEY_INDEX $REMOTE_PUBKEY_INDEX..."
TOsh.py renew_shared_keys $REMOTE_PUBKEY_INDEX $REMOTE_PUBKEY_INDEX
if [ $? -ne 0 ]
then
        echo "Unable to set renew shared keys"
        exit 4
fi

exit 0
