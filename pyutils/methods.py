"""
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

Copyright 2016 Trusted Objects

@brief       Secure Element Python utils: tools to use Secure Element libraries
@author      Trusted-Objects
"""

import sys
import array
import os.path
import ctypes
from ctypes.util import find_library
from codecs import encode, decode
from importlib import import_module

global methods

methods = {}

def register(name, in_params=None, out_params=None, labels=None):
    """ Decorator to register callback
    """
    def func_wrapper(func):
        global methods
        methods[name] = {'func': func, 'in': in_params, 'out': out_params ,
                'labels': labels}
        return func
    return func_wrapper

def unknown(*args, **kwargs):
    print("UNKNOWN")

def decode_string(s):
    """ Helper to convert hexadecimal string from client
    """
    if 0 != len(s) % 2:
        s = '0x0' + s # add padding
    return decode(bytes(
        ''.join(s.split(' ')).replace('0x', '').replace('0X', ''), 'ascii'),
        'hex')

def encode_hex(value):
    return value and encode(value, 'hex') or b''

def load_library(library_name, module_name):
    """ Load the requested library and the corresponding methods module
    """
    if sys.platform.startswith('linux'):
        library = ctypes.cdll.LoadLibrary(find_library(library_name))
    else:
        library = ctypes.CDLL('lib' + library_name)
    module = import_module(module_name)
    module.__init__(library)
