import random
import math
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

q = 11
p = 17

def calculateN():
    return q * p

def getIntegerE(eulerTotientFn):
    while True:
        e = random.randint(2, eulerTotientFn - 1)
        if math.gcd(e, eulerTotientFn) == 1:  # Ensure e is coprime with eulerTotientFn
            return e

def find_d(e, L):
    # calculate the modular inverse
    d = pow(e, -1, L)
    return d

def encrypt(M, e, n):
    return pow(M, e, n)

if __name__ == "__main__":
    # Key generation steps
    n = calculateN()
    eulerTotientFn = (p - 1) * (q - 1)
    
    e = getIntegerE(eulerTotientFn)
    d = find_d(e, eulerTotientFn)
    
    publicKey = (e, n)
    privateKey = (d, n)
    
    # Encryption
    M = 88  # The plaintext
    ciphertext = ''
    if M < n:
        ciphertext = encrypt(M, e, n)
        print("ciphertext is ... " + str(ciphertext))
    else:
        print("Invalid plaintext! ... Exiting \n")
