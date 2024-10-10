# implementing the key exchange logic where Alice sends q=37 and apha = 5
import random


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
    alice_key = getRandomInteger()
    # Bob's private key
    bob_key = getRandomInteger()

    # Alice's public key
    alice_public_key = getPublicKey(alice_key)

    # Bob's public key
    bob_public_key = getPublicKey(bob_key)

    # now need to generate a secret key that is only shared between alice and bob
    # Private Key from Alice Request
    print("alice shared key is " , getSecretKey(alice_key, bob_public_key))
    # Private Key from Bob Request
    print("bob shared key is " , getSecretKey(bob_key, alice_public_key))

