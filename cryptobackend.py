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
from entpool import EntropyPool
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
    def __init__(self,load:bool,generate:bool,KeyfileName:str, bitlength = 32):
        self.bitsize = bitlength
        if generate == True:
            self.CreateKeyFernet(KeyfileName)

    def CreateKeyFernet(self,name:str):
        """Generates a key and save it into a file"""
        key = Fernet.generate_key()
        key_file = open(name, "wb", encoding = "utf-8")
        key_file.write(key)
        key_file.close()

    
    def CreateKeySecrets(self):
        return secrets.randbits(self.bitsize)

    def LoadKeyFernet(self,name:str):
        """Loads the key from the current directory."""
        return open(name, "rb").read()

class Hash():
    '''implementation of multiple hashing algorhithms to obtain key bytes from 
a string and salt
typeofhash = "sha256" || "sha512" || "md5"
'''
    def __init__(self, typeofhash:int, password:str):
        #after salting the passwords with a PBKDF...
        self.type   = typeofhash
        try:
            if typeofhash == "sha256":
                self.Digest = self.sha256(bytes(password))
            elif typeofhash=="sha512":
                self.Digest = self.sha512(bytes(password))
            elif typeofhash == "md5":
                self.Digest = self.md5(bytes(password))
            else:
                raise Exception
        except Exception:
            print("[-] Error in HashString.__init__")
            SystemExit

    def md5(self,keybytes:bytes):
        ''' returns a sha512 digest of a password after salting with PBKDF'''
        herp = hashlib.md5()
        herp.update(keybytes)
        return herp.digest()

    def sha256(self,keybytes:bytes,encoding =  "utf-8"):
        ''' returns a sha256 digest of a password after salting with PBKDF'''
        herp = hashlib.sha256()
        herp.update(keybytes)
        return herp.digest()

    def sha512(self,keybytes:bytes,encoding =  "utf-8"):
        ''' returns a sha512 digest of a password after salting with PBKDF'''
        herp = hashlib.sha512()
        herp.update(keybytes)
        return herp.digest()

class Seed():
    '''You must invoke a high entropic value in the system from which a
 ciphertext is derived from a plaintext'''
    def __init__(self,source = "internal"):

        pass

class PBKDF():
    '''Implementation of multiple Password Based Key Derivation Algorhithms
    password and salt must be bytes-like objects. 
    salt should be about 16 or more bytes from a proper source    
        n      = CPU/Memory cost factor
        r      = block size
        p      = parallelization factor 
        maxmem = limits memory 
                    - (OpenSSL 1.1.0 defaults to 32 MiB). 
        dklen  = length of the derived key.
'''
    def __init__(self, salt:str, password:str, bitsrequired:int):
        pass

    def pbkdf2(self, type:str,password:bytes,salt:bytes):
        '''returns the hex encoding of the key, derived from a password string'''
        derivedkey = hashlib.pbkdf2_hmac(type, password, salt, 100000)
        return derivedkey.hex()

    def ScryptKey(self, password,salt,n,r,p):
        '''returns the hex encoding of the key, derived from a password string'''
        derivedkey = hashlib.scrypt(password, salt, n, r, p, maxmem=0, dklen=64)
        return derivedkey.hex()

class Salt():
    '''used to generate a salt
    Salt factor 5 seems reasonable at first glance
    itteration value
    '''
    def __init__(self,bytesize:int, saltfactor = 5):
        self.entropypoolcoefficient = saltfactor
        self.poursalt(bytesize)
    
    def poursalt(self, bytesize:int):
        herp = EntropyPool(bytesize, 3)
        #return herp.SaltMine(bytesize)

class Encrypt():
    ''''''
    def __init__(self, plaintext, salt, password):
        pass
    
    def Fernet(self, key, salt, plaintext):
        herp = Fernet(key)
        ciphertext = herp.encrypt(plaintext)
        return ciphertext
    
    def aesGCM(self):
        pass

class Decrypt():
    def __init__(self):
        pass

    def Fernet(self, key, salt, plaintext):
        herp = Fernet(key)
        ciphertext = herp.decrypt(plaintext)
        return ciphertext
