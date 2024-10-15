# implementing the key exchange logic where Alice sends q=37 and apha = 5
import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
q = 11
p = 17

def calculateN():
    return q * p

def getIntegerE(eulerTotientFn):
    return random.randint(1,eulerTotientFn)

def find_d(e, L):
    # Using Python's pow() to calculate the modular inverse
    d = pow(e, -1, L)
    return d

if __name__ == "__main__":
    # key generation steps
    n = calculateN()
    eulerTotientFn = (p-1)*(q-1)
    e = getIntegerE(eulerTotientFn)
    d = find_d(e, eulerTotientFn)
    publicKey = (e, n)
    privateKey = (d, n)
