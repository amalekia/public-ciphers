import random
import math
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number


# utility function for the variable length primes
def generatePrime(bits=2048):
    return number.getPrime(bits)


def calculateN(q, p):
    return q * p

# def getIntegerE(eulerTotientFn):
#     while True:
#         e = random.randint(2, eulerTotientFn - 1)
#         if math.gcd(e, eulerTotientFn) == 1:  # Ensure e is coprime with eulerTotientFn
#             return e

def find_d(e, L):
    # calculate the modular inverse
    d = pow(e, -1, L)
    return d

def encrypt(M, e, n):
    return pow(M, e, n)

def decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)

def textbookRSAHelper():
    q = generatePrime()
    p = generatePrime()
    
    # Key generation steps
    n = calculateN(q, p)
    eulerTotientFn = (p - 1) * (q - 1)
    
    # e = getIntegerE(eulerTotientFn)
    e = 65537
    d = find_d(e, eulerTotientFn)
    return (e, n, d)

def textbookRSA():
    (e, n, d) = textbookRSAHelper()
    # Encryption
    M = 88  # The plaintext
    ciphertext = ''
    if M < n:
        ciphertext = encrypt(M, e, n)
        print("ciphertext is ... " + str(ciphertext))
    else:
        print("Invalid plaintext! ... Exiting \n")

    # decryption
    decryptedMessage = decrypt(ciphertext, d, n)
    print("decryptedMessage is ... " + str(decryptedMessage))

def encrypt_plaintext(message, key, iv):
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    
    # Pad the message to be a multiple of 16 bytes
    padded_message = pad(message, AES.block_size)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(padded_message)
    
    return iv + ciphertext

def decrypt_plaintext(ciphertext, key):
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_CBC, iv=ciphertext[:AES.block_size])
    
    # Decrypt the message
    decrypted_message = cipher.decrypt(ciphertext[AES.block_size:])
    
    # Unpad the message to get the original plaintext
    plaintext = unpad(decrypted_message, AES.block_size)
    
    return plaintext

if __name__ == "__main__":
    # textbookRSA implementation first
    # textbookRSA();


    # Alice gets public and private key
    (e, n, d) = textbookRSAHelper()
    
    alice_publicKey = (e, n)
    alice_privateKey = (d, n)

    # Bob calculates secret key S
    s = random.randint(1, n)
    c = pow(s, e, n)

    # Mallory intercepts c
    # need some value of c' such that we always get an expected s value
    c_prime = n
    # Mallory sends this c' value to Alice now

    # Alice recieves "c" but it is really just c'
    # Alice decrypts c' with her private key
    s_prime = decrypt(c_prime, d, n)
    
    # Alice uses this s_prime to generate a key for AES symmetric encryption
    # Create SHA256 hash object
    hash_obj = SHA256.new()
    hash_obj.update(s_prime.to_bytes((s_prime.bit_length() + 7) // 8))   
     
    # Get the hash value and truncate to 16 bytes
    k = hash_obj.digest()[:16]

    # now, Alice wants to wants to use the AES symmetric encryption to send text to Bob
    # but it will be intercepted by Alice
    with open('./aliceText.txt', 'rb') as f:
        plaintext = f.read()
    encrypted_ciphertext = encrypt_plaintext(plaintext, k, random.randbytes(AES.block_size))
                                             
    # now, Alice sends this encrypted_ciphertext to "Bob", but only "Mallory" can intercept it
    # since Mallory knows the s value

    decrypted = decrypt_plaintext(encrypted_ciphertext, k)
    print("Mallory decrypted it ", decrypted)



