#!/usr/bin/env python3

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def createKeyGenerator():
   return dh.generate_parameters(generator=2, key_size=512, 
                                 backend=default_backend())

def createCipher(sharedSecret):
   # the msg must be multiple of block_size
   block_size = 16
   iv = os.urandom(block_size)
   return Cipher(algorithms.AES(sharedSecret), modes.CBC(iv), 
                 backend=default_backend())

# Generate a pair of public and private keys
def generateKeys(keyGenerator):
   privateKey = keyGenerator.generate_private_key()
   publicKey = privateKey.public_key()
   return privateKey, publicKey

def computeSharedSecret(myPrivateKey, otherPublicKey):
   shared_key = myPrivateKey.exchange(otherPublicKey)

   sharedSecret = HKDF(
         algorithm=hashes.SHA256(),
         length=32,
         salt=None,
         info=b'handshake data',
         backend=default_backend()
      ).derive(shared_key)   
   
   return sharedSecret

# Encrypt the message using symmetric encryption.
# sharedSecret is the shared secret and msg is a string containing the 
# message to encrypt. Returns a stream of bytes
# Warning: the cipher used must be the same for encryption than for decryption. 
def encryptMessage(cipher, msg):
   # TODO: fix msg size to 256. Give an error if len(msg) > msg_size
   encryptor = cipher.encryptor()
   e = encryptor.update(msg.encode()) + encryptor.finalize()
   return e

# Decrypt the message using symmetric encryption.
# sharedSecret is the shared secret and msg is an array of bytes containing
# the encrypted message. Returns a string
def decryptMessage(cipher, msg):
   # TODO: fix msg size to 256. Give an error if len(msg) > msg_size
   decryptor = cipher.decryptor()
   dt = decryptor.update(msg) + decryptor.finalize()
   return dt.decode()


def testEncryption():
   print("v8")
   keyGenerator = createKeyGenerator()
   
   a_private_key, a_peer_public_key = generateKeys(keyGenerator)
   b_private_key, b_peer_public_key = generateKeys(keyGenerator)
   
   a_shared_secret = computeSharedSecret(a_private_key, b_peer_public_key)
   b_shared_secret = computeSharedSecret(b_private_key, a_peer_public_key)
   
   msg = "16 chars msg...."
   
   
   #e = encryptMessage(a_shared_secret, msg)
   #d = decryptMessage(a_shared_secret, e)
   
   
   
   cipher = createCipher(a_shared_secret)
   e = encryptMessage(cipher, msg)
   cipher = createCipher(a_shared_secret)
   answer = decryptMessage(cipher, e)

   
   
   if a_shared_secret != b_shared_secret:
      print("FAILURE: shared secret different")
   elif answer != msg:
      print("FAILURE: on encryption")
   else:
      print("SUCESS")
   
   
   
   
   
   






