# implementing the key exchange logic where Alice sends q=37 and apha = 5
import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

q = 37
alpha = 5

# Function that picks a random positive integer 
# this will be called by Alice and Bob to generate
# their public key

def getRandomInteger():
    return random.randint(1, 100)

def getPublicKey(privateKey):
    return (alpha**privateKey) % q

def getSecretKey(privateKey, publicKey):
    return (publicKey**privateKey) % q

def generateSharedKey():
    # Alice's private key
    alice_private_key = getRandomInteger()
    # Bob's private key
    bob_private_key = getRandomInteger()

    # Alice's public key
    alice_public_key = getPublicKey(alice_private_key)

    # Bob's public key
    bob_public_key = getPublicKey(bob_private_key)

    # now need to generate a secret key that is only shared between alice and bob
    # Private Key from Alice Request
    shared_key_alice = getSecretKey(alice_private_key, bob_public_key)
    # Private Key from Bob Request
    shared_key_bob = getSecretKey(bob_private_key, alice_public_key)

    # we now feed the secret key to the SHA256 function to generate a key that can be used for AES_CBC tasks
     # Check if both keys are the same
    if shared_key_alice == shared_key_bob:
        # Convert the shared key to bytes
        shared_key_bytes = str(shared_key_alice).encode('utf-8')
        
        # Create SHA256 hash object
        hash_obj = SHA256.new()
        hash_obj.update(shared_key_bytes)
        
        # Get the hash value and truncate to 16 bytes
        hashed_key = hash_obj.digest()[:16]
        return hashed_key
    else:
        return None

def encrypt_plaintext(message, key):
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Pad the message to be a multiple of 16 bytes
    padded_message = pad(message, AES.block_size)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(padded_message)
    
    return ciphertext
        
def decrypt(ciphertext, key):
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt the message
    decrypted_message = cipher.decrypt(ciphertext)
    
    # Unpad the message to get the original plaintext
    plaintext = unpad(decrypted_message, AES.block_size)
    
    return plaintext

if __name__ == "__main__":
    hashed_key = generateSharedKey()
    if (hashed_key == None):
        print("error")
    else:

    # now we need to emulate AES encryption using hashed_key as key
    # for message transfer between Alice and Bob
        with open('./aliceCipherText.txt', 'rb') as f:
            plaintext = f.read()

        alice_ciphertext = encrypt_plaintext(plaintext, hashed_key)
        # write alice encrypted cipher text to file for Bob to listen to
        with open('./aliceCipherText.bmp', 'wb') as f:
            f.write(alice_ciphertext)

        # Bob needs to read that ciphertext and decrypt it
        with open('./aliceCipherText.bmp', 'rb') as f:
            bob_to_read_ciphertext = f.read()

        print("bob_to_read cipher text is \n", bob_to_read_ciphertext)
        decrypted = decrypt(bob_to_read_ciphertext, hashed_key)
        # bob writes the decrypted message alice sent to this file
        with open('./decrypted_alice_ciphertext.txt', 'wb') as f:
            f.write(decrypted)
    