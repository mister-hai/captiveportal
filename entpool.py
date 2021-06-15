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

This tutorial uses code from the following sources:
https://github.com/yinengy/Mersenne-Twister-in-Python
https://github.com/AllenDowney/PythonCounterPmf/

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
        pmf = MassProbabilityFunction()
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
    
class MersenneTwist():
    def __init__(self):
        # coefficients for MT19937
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        self.a = 0x9908B0DF
        (self.u, self.d) = (11, 0xFFFFFFFF)
        (self.s, self.b) = (7, 0x9D2C5680)
        (self.t, self.c) = (15, 0xEFC60000)
        self.l = 18
        self.f = 1812433253
        # make an array to store the state of the generator
        self.MT = [0 for i in range(self.n)]
        self.index = self.n+1
        self.lower_mask = 0xFFFFFFFF #int(bin(1 << r), 2) - 0b1
        self.upper_mask = 0x00000000 #int(str(-~lower_mask)[-w:])
        
        #print(extract_number())
    
    def seedtwister(self,seed):
        '''initialize the generator from a seed'''
        self.mt_seed(seed)

    def mt_seed(self, seed):
        # global self.index = int
        # self.index = n
        self.MT[0] = seed
        for i in range(1, self.n):
            temp = self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i
            self.MT[i] = temp & 0xffffffff

    # Extract a tempered value based on MT[index]
    # calling twist() every n numbers
    def extract_number(self):
        ''' call this function after MersenneTwist.seedtwister(seed)
 to return a value'''
        self.index = int
        if self.index >= self.n:
            self.twist()
            self.index = 0

        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ (y >> self.l)

        self.index += 1
        return y & 0xffffffff
    
    # Generate the next n values from the series x_i
    def twist(self):
        for i in range(0, self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA

class XORShift():
    def __init__(self):
        pass

    def VonNeumanExtractor(self, data1,data2):
        '''Von Neumann extractor 
    can be shown to produce a uniform output even if the distribution 
    of input bits is not uniform so long as:
        - each bit has the same probability of being one 
        - there is no correlation between successive bits.
    
From Wikipedia:
   From the input stream, his extractor took bits, two at a time 
   (first and second, then third and fourth, and so on). 
   If the two bits matched, no output was generated. 
   If the bits differed, the value of the first bit was output. 
'''
        datafield = []
        try:
            for bytefield1,bytefield2 in data1,data2:
                if bytefield1 == bytefield2:
                    #discard the number
                    pass
                elif bytefield1 != bytefield2:
                    #save the number
                    datafield.append(bytefield1)
        except Exception:
            error_printer("[-] Von Neuman Extractor failed:")
        return datafield

    def XORBox(self, seed, number_of_itterations):
        '''Performs XOR and shuffling operations on a grid of PRN/CSPRN
        to simply generate an even more secure byte array...
        and i still dont understand how randomness is a thing for a number '''
        XORFinal = []
        datafield = []

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
                self.VonNeumanExtractor(XORFinal, datafield)
        except Exception:
            error_printer("[-] Could not XOR bytes: ")
        return XORFinal


class EntropyPool():
    '''Holds A pool of entropic value
Final pool is held in self.output
'''
    def __init__(self, bytesize:int, scalingfactor:int, method = "xor"):
        #setup the system in order
        self.pool = []
        self.bytesize = bytesize
        self.output = list
        self.randomnesscheck = MassProbabilityFunction()

    def uniformity(self, x):
        '''Will return a number describing the uniformity of the data fed to it
Accepts arrays of integers/floats'''
        return lambda x : 1 - 0.5*sum( abs(x - numpy.average(x)) )/(len(x)*numpy.average(x))

    def gettime(self):
        timenow = time.time()
        return timenow
    
    def gettimenanosec(self):
        timenow = time.time_ns()
        return timenow

    def SaltMine(self, bytesize, number_of_itterations, seed):
        '''Derives good random numbers from a variety of sources
    - Will itterate the operation the specified number of times
    - Performs an XOR Shuffle on a set of PRN generated by a Mersenne Twister'''
        try:
            xorstuff = XORShift()
            # setup the mersenne twister to begin generating numbers
            twister = MersenneTwist()
            twister.seedtwister(seed)
            for x in range(number_of_itterations):
                self.pool.append(twister.extract_number())
            for seedbytes in self.pool:
                self.output.append(xorstuff.XORBox(seedbytes, number_of_itterations))

        except Exception:
            error_printer("[-] Could not Create Randomness")
        
    def source1(self):
        '''return os.urandom(self.bytesize)'''
        return os.urandom(self.bytesize)

    def source2(self):
        '''return secrets.randbits(self.bytesize)'''
        return secrets.randbits(self.bytesize)
    
    def source3(self):
        '''return self.gettimenanosec()'''
        return self.gettimenanosec()

class EntropyPoolHandler():
    '''Entropy Pool management
    Will Create an EntropyPool() Class and seed it with a decent set of random data,
    from pre-established sources of known good Pseudo Random Numbers.

This is the Function to call externally'''
    def __init__(self, bytearraylength = 32):
        scalingfactor = 1
        # we need to perform sorting operations and metrics so 
        # we instantiate multiple handlers to perform those operations
        NewPool = EntropyPool(bytearraylength, scalingfactor)
        NewPool.SaltMine(bytearraylength ,scalingfactor,NewPool.source1)