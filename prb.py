# prb.pyclass 
# Author: John Clark Craig  (Commented and documented by Andrew Scott)
# URL: https://jccraig.medium.com/python-pseudorandom-bytes-143462fb0afe 

# A pseudo random byte generator for use in Python.

class Prb:
    def __init__(self, seed):
        '''
        Initializes the pseudo random byte generator. The Prb class is initialized by passing 
        a seed string. 
        If even one bit of this string is changed, the output sequence of bytes is instantly and 
        completely changed going forward.   You can change the output further by applying your own 
        string to the seed, so that from one implimentation to another the output  for any given 
        seed value may be unique to that implimentaion. However, because of this the cipher that 
        uses this will be non standardized 
        and this is a drawback of this PRBG.
        paramters:
            seed: A seed string.  
        '''

        #The seed value, the sequence generated is unique to this.
        unique_seed = seed + "Customize here"

        len_unique_seed = len(unique_seed)
        self.p, self.q = 0, 0  
        self.buf = list(range(256))#Initialize buffer of 256 values.

        # Via to calls to the next_byte() function, the value of p and q are altered with each 
        # step by the byte values of the seed string, and also by the byte values at the buffer 
        # locations they point to.
        for i in range(997):#Warmup phase
            n = ord(unique_seed[i % len_unique_seed])
            self.next_byte(n + self.next_byte())    
                
    def next_byte(self, b=0):
        '''
        Generates the next pseudo random byte in the sequence each time it is called.
        The valie of p and q are first bassed of of the value at the buffer index p or 
        q + b with a +1 or +2 added to force divergence. The value of p and q are then 
        each brought into the range 0 to 255 using the mod operator, and the bytes pointed 
        to in the buffer by their new values are swapped. Finally, the values  of p and q 
        are XOR’d together to create the byte returned by the method.
        parameters:
            b (number): An optional byte (or larger) value.  The values of p and q are modified by adding 
                        this optional value with the buffer bytes they each point to, plus either 1 or 2 to 
                        force their divergence.
        returns:
            self.p ^ self.q to provide the next byte in the sequence.
        '''
        #get value at index p in buffer add b  then 1 and mod by the buffer size, store in p
        self.p = (self.buf[self.p] + b + 1) % 256
        #get value at index q in buffer add b then 2 and mod by the buffer size, store in q
        self.q = (self.buf[self.q] + b + 2) % 256

        #Swap the values at index p and q in the buffer
        self.buf[self.p], self.buf[self.q] = self.buf[self.q],   self.buf[self.p]
        return self.p ^ self.q