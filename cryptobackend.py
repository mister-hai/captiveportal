# -*- coding: utf-8 -*-
#!/usr/bin/python3.9
################################################################################
##   Crypto tools and control flows for hacking - Vintage 2021 Python 3.9     ##
################################################################################                
# Licenced under GPLv3-modified                                               ##
# https://www.gnu.org/licenses/gpl-3.0.en.html                                ##
#                                                                             ##
# The above copyright notice and this permission notice shall be included in  ##
# all copies or substantial portions of the Software.                         ##
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
################################################################################
""""""
TESTING = True
import sys,os
import hashlib
import crypto
from binascii import hexlify

class HashString():
    '''implementation of multiple hashing algorhithms to obtain key bytes from 
a string and salt

typeofhash = "sha256" || "sha512" || "md5"

>>> import hashlib
>>> m = hashlib.sha256()
>>> m.update(b"Nobody inspects")
>>> m.update(b" the spammish repetition")
>>> m.digest()
    b'\x03\x1e\xdd}Ae\x15\x93\xc5\xfe\\\x00o\xa5u+7\xfd\xdf\xf7\xbcN\x84:\xa6\xaf\
    x0c\x95\x0fK\x94\x06'
>>> m.digest_size
    32
>>> m.block_size
    64
---OR---
hashlib.sha224(b"Nobody inspects the spammish repetition").hexdigest()
'a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2'
--- AND ---
>>> h = hashlib.new('sha512_256')
>>> h.update(b"Nobody inspects the spammish repetition")
>>> h.hexdigest()
'19197dc4d03829df858011c6c87600f994a858103bbc19005f20987aa19a97e2'

'''
    def __init__(self, typeofhash:int):
        pass


class Seed():
    '''You must invoke a high entropic value in the system from which a
 ciphertext is derived from a plaintext'''
    def __init__(self):
        pass

class PBKDF():
    '''Implementation of multiple Password Based Key Derivation Algorhithms
>>> import hashlib
>>> dk = hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 100000)
>>> dk.hex()
    '0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5
--- OR ---
hashlib.scrypt(password, *, salt, n, r, p, maxmem=0, dklen=64)
    The function provides scrypt password-based key derivation function 
        - defined in RFC 7914.
    password and salt must be bytes-like objects. 
    Applications and libraries should limit password to a sensible length 
        - e.g. 1024 
    salt should be about 16 or more bytes from a proper source
        - e.g. os.urandom()
    
        n      = CPU/Memory cost factor
        r      = block size
        p      =  parallelization factor 
        maxmem =  limits memory 
                    - (OpenSSL 1.1.0 defaults to 32 MiB). 
        dklen  = length of the derived key.
    
    Availability: OpenSSL 1.1+.
    New in version 3.6.
'''
    def __init__(self, salt:str, password:str, bitsrequired:int):
        pass

class Salt():
    def __init__(self):
        self.salt = os.urandom(16)

        pass
    
class Encrypt():
    def __init__(self, plaintext, salt, password):
        pass

class Decrypt():
    def __init__(self):
        pass
