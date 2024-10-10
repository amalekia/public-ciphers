# implementing the key exchange logic where Alice sends q=37 and apha = 5
import random
from Crypto.Hash import SHA256


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

if __name__ == "__main__":
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
        print("Hashed key is:", hashed_key)
    else:
        print("Keys do not match!")
    
    # we will use this hashed_key for the AES algorithms