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
import secrets
import cryptography
from cryptography.fernet import Fernet
from binascii import hexlify
from backendDB import redprint,greenprint,blueprint,makeyellow
from backendDB import info_message,critical_message,is_method
from backendDB import yellow_bold_print

class Key():
    ''' turns a string into a key byte array, or generates a secure random key'''
    def __init__(self,load:bool,generate:bool,KeyfileName:str):
        if generate == True:
            self.CreateKeyFernet(KeyfileName)

    def CreateKeyFernet(self,name:str):
        """Generates a key and save it into a file
>>> f = Fernet(key)
>>> token = f.encrypt(b"A really secret message. Not for prying eyes.")
>>> token
    b'...'
>>> f.decrypt(token)
    b'A really secret message. Not for prying eyes.'
"""
        key = Fernet.generate_key()
        key_file = open(name, "wb", encoding = "utf-8")
        key_file.write(key)
        key_file.close()

    
    def CreateKeySecrets(self):
        return secrets.randbits(self.bitsize)

    def LoadKeyFernet(self,name:str):
        """
Loads the key named `secret.key` from the current directory.

"""
        return open(name, "rb").read()

class HashString():
    '''implementation of multiple hashing algorhithms to obtain key bytes from 
a string and salt

typeofhash = "sha256" || "sha512" || "md5"

hashlib.sha224(b"Nobody inspects the spammish repetition").hexdigest()
'a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2'
--- AND ---
>>> h = hashlib.new('sha512_256')
>>> h.update(b"Nobody inspects the spammish repetition")
>>> h.hexdigest()
'19197dc4d03829df858011c6c87600f994a858103bbc19005f20987aa19a97e2'

'''
    def __init__(self, typeofhash:int, string:str):
        try:
            if typeofhash == "sha256":
                pass
            elif typeofhash=="sha512":
                pass
            elif typeofhash == "md5":
                pass
            else:
                raise Exception
        except Exception:
            print("[-] Error in HashString.__init__")
            SystemExit

    def sha256(self,keystring:str,encoding =  "utf-8"):
        ''' returns a sha256 digest of a password'''
        m = hashlib.sha256()
        m.update(bytes(keystring),encoding)
        m.update(b" the spammish repetition")
        return m.digest()

    def sha512(self,keystring:str,encoding =  "utf-8"):
        ''' returns a sha512 digest of a password'''
        m = hashlib.sha512()
        m.update(bytes(keystring),encoding)
        m.update(b" the spammish repetition")
        return m.digest()

class Seed():
    '''You must invoke a high entropic value in the system from which a
 ciphertext is derived from a plaintext'''
    def __init__(self,source = "internal"):

        pass

class PBKDF():
    '''Implementation of multiple Password Based Key Derivation Algorhithms

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

    def pbkdf2(self, type:str,password:bytes,salt:bytes):
        derivedkey = hashlib.pbkdf2_hmac(type, password, salt, 100000)
        return derivedkey.hex()

    def ScryptKey(self, password,salt,n,r,p):
        hashlib.scrypt(password,*,salt, n, r, p, maxmem=0, dklen=64)

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
