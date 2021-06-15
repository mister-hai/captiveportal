# -*- coding: utf-8 -*-
#!/usr/bin/python3.9
################################################################################
##       Entropy thing for learning/hacking - Vintage 2021 Python 3.9         ##
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
"""Entropy Pool?
 hmac.new(key, msg=None, digestmod='')
    Return a new hmac object. key is a bytes or bytearray object giving the 
    secret key. If msg is present, the method call update(msg) is made. 
    digestmod is the digest name, digest constructor or module for the HMAC 
    object to use. It may be any name suitable to hashlib.new(). Despite its 
    argument position, it is required.
    Changed in version 3.4: Parameter key can be a bytes or bytearray object. 
    Parameter msg can be of any type supported by hashlib. Parameter digestmod 
    can be the name of a hash algorithm.

HMAC.update(msg)
    Update the hmac object with msg. Repeated calls are equivalent to a single 
    call with the concatenation of all the arguments: m.update(a); m.update(b) 
    is equivalent to m.update(a + b).
    Changed in version 3.4: Parameter msg can be of any type supported by hashlib.

HMAC.digest()
    Return the digest of the bytes passed to the update() method so far. This bytes 
    object will be the same length as the digest_size of the digest given to the 
    constructor. It may contain non-ASCII bytes, including NUL bytes.
    When comparing the output of digest() to an externally-supplied digest during a 
    verification routine, it is recommended to use the compare_digest() function 
    instead of the == operator to reduce the vulnerability to timing attacks.

HMAC.hexdigest()
    Like digest() except the digest is returned as a string twice the length 
    containing only hexadecimal digits. This may be used to exchange the value safely 
    in email or other non-binary environments.
    When comparing the output of hexdigest() to an externally-supplied digest during a 
    verification routine, it is recommended to use the compare_digest() function 
    instead of the == operator to reduce the vulnerability to timing attacks.

Claude Shannon's definition of self-information was chosen to meet several axioms:
    - An event with probability 100% is perfectly unsurprising and yields no information.
    - The less probable an event is, the more surprising it is and the more information it yields.
    - If two independent events are measured separately, the total amount of information 
      is the sum of the self-informations of the individual events.
""" 
#t = Timer(...)       # outside the try/except
#try:
#    t.timeit(...)    # or t.repeat(...)
#except Exception:
#    t.print_exc()
# I have no fucking idea what I am doing
TESTING = True
import hmac
import time
import numpy
import sys,os
import hashlib
import secrets
import cryptography
from binascii import hexlify
from collections import Counter
from cryptography.fernet import Fernet
from backendDB import redprint,greenprint,blueprint,makeyellow,error_printer

# the idea of this is to have multiple sources of randomness and 
# XOR/HMAC them into a single byte array of fixed length for the purposes of 
# CSPRNG

class MassProbabilityFunction(Counter):
    """Probability Distribution - Mass Probability"""

    def normalize(self):
        """Normalizes the PMF so the probabilities add to 1."""
        total = float(sum(self.values()))
        for key in self:
            self[key] /= total

    def __add__(self, other):
        """
Adds two distributions.
The result is the distribution of sums of values from the two.
        """
        pmf = Pmf()
        for key1, prob1 in self.items():
            for key2, prob2 in other.items():
                pmf[key1 + key2] += prob1 * prob2
        return pmf

    def __hash__(self):
        """Returns an integer hash value."""
        return id(self)
    
    def __eq__(self, other):
        return self is other

    def render(self):
        """Returns values and their probabilities, suitable for plotting."""
        return zip(*sorted(self.items()))

    def is_subset(self, other):
        """Checks whether self is a subset of other. """
        for char, count in self.items():
            if other[char] < count:
                return False
        return True
    

class EntropyPool():
    '''Holds A pool of entropic value'''
    def __init__(self, bytesize:int, scalingfactor:int, method = "xor"):
        #setup the system in order
        self.pool = dict
        self.mixingmethod = method
        self.bytesize = bytesize
        self.scalingfactor = self.finalizescaling(scalingfactor)
        self.SaltMine(self.bytesize,self.mixingmethod)

    def finalizescaling(self, inputplustuff):
        scalingfactor = inputplustuff
        return scalingfactor

    def gettime(self):
        timenow = time.time()
        return timenow
    
    def gettimenanosec(self):
        timenow = time.time_ns()
        return timenow
    
    def fillpool(self):
        '''populate a dict with random values'''
        pass

    def SaltMine(self, bytesize, method:str, number_of_itterations):
        '''Derives good random numbers from a variety of sources
    method == "xor" || "hmac"

Will itterate the operation the specified number of times  '''
        try:
            if method == "xor":
                self.XORBox(number_of_itterations)
            elif method == "hmac":
                self.hmac(self.source1(),self.source2(), number_of_itterations)
            else:
                raise Exception
        except Exception:
            error_printer("[-]")
        
    def source1(self):
        '''return os.urandom(self.bytesize)'''
        return os.urandom(self.bytesize)

    def source2(self):
        '''return secrets.randbits(self.bytesize)'''
        return secrets.randbits(self.bytesize)
    
    def source3(self):
        '''return self.gettimenanosec()'''
        return self.gettimenanosec()

    def hmac(self, data1:bytes, data2:bytes, number_of_itterations):
         hmac.new(data1, msg=data2, digestmod='')


    def XORBox(self, number_of_itterations):
        '''Performs XOR and shuffling operations on a grid of PRN/CSPRN
        to simply generate an even more secure byte array...
        and i still dont understand how randomness is a thing for a number '''
        XORFinal = []
        datafield = []
        #d1len = len(data1)
        #d2len = len(data2)
        try:
            # to begin with, we wrap everything in an itterator to perform 
            # multiple passes of the XOR/shift, allowing us to use the randomness
            # extractor to create a new number 
            for current_itteration in range(number_of_itterations): 
            # think of this loop as defining an X,Y coordinate system
            # we are taking byte fields and stretching them into a line
            # equal to thier size
            # but one number (index) we define on the fly, inside the loop
            # for x_coordinate in y_coordinate:
                for index in datafield:
                    # index + 1 is over one column to the right
                    # index - 1 is to the left
                    # Row A is this loop here, each data item is a Row
                    for byte in datafield[index == 0]:
                        # row operations
                        # use index to access other rows as thus:
                        # data2[index] == data1[index] == current column, named row
                        pass
                    #Row B
                    for byte in datafield[index == 1]:
                        #row operations
                        pass
                    # ... And so on

        except Exception:
            error_printer("[-] Could not XOR bytes: ")
        return XORFinal

class EntropyPoolHandler():
    '''Entropy Pool management
    Will Create an EntropyPool() Class and seed it with a decent set of random data,
    from pre-established sources of known good Pseudo Random Numbers.

This is the Function to call externally'''
    def __init__(self, bytearraylength = 32):
        scalingfactor = 1
        NewPool = EntropyPool(bytearraylength, scalingfactor)
        NewPool.SaltMine
    
    def uniformity(self, x):
        '''Will return a number describing the uniformity of the data fed to it
Accepts arrays of integers/floats'''
        return lambda x : 1 - 0.5*sum( abs(x - numpy.average(x)) )/(len(x)*numpy.average(x))