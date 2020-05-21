#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization

from random import randrange

from string import ascii_letters
from random import choice

def createRandomMessage(messageSize):
   chars = ascii_letters + ".,:;-+*/?!()[]{}"
   return ''.join(choice(chars) for i in range(messageSize))

def createKeyGenerator():
   return dh.generate_parameters(generator=2, key_size=512, 
                                 backend=default_backend())

def createCipher(sharedSecret):
   # iv initialization vector is a 16 block of random bytes generated 
   # by os.urandom(16)
   iv = b'+\xed6\xdd\xf0\xb1\x17\xa2\xa7\x12\x13\xd3\xd0\xf9\x14\xac'
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
def encryptMessage(shared_secret, msg):
   padder = padding.PKCS7(128).padder()
   padded_data = padder.update(msg.encode()) + padder.finalize()
   
   cipher = createCipher(shared_secret)
   encryptor = cipher.encryptor()
   e = encryptor.update(padded_data) + encryptor.finalize()
   return e

# Decrypt the message using symmetric encryption.
# sharedSecret is the shared secret and msg is an array of bytes containing
# the encrypted message. Returns a string
def decryptMessage(shared_secret, msg):
   cipher = createCipher(shared_secret)
   decryptor = cipher.decryptor()
   dt = decryptor.update(msg) + decryptor.finalize()
   
   unpadder = padding.PKCS7(128).unpadder()
   unpadded_data = unpadder.update(dt) + unpadder.finalize()
   
   return unpadded_data.decode()

# Given a RSA public key, returns it serialization in bytes
def serializePublicKey(public_key):
   return public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
   )

# Given a bytes stream representing a RSA public key, 
# returns a public key object
def deserializePublicKey(public_key_bytes):
   return serialization.load_pem_public_key(public_key_bytes, 
                                            backend=default_backend())
   
def testEncryption():
   keyGenerator = createKeyGenerator()
   
   a_private_key, a_public_key = generateKeys(keyGenerator)
   b_private_key, b_public_key = generateKeys(keyGenerator)
   error = False
   
   for _ in range(10000):
      size = randrange(10, 256)
      msg = createRandomMessage(size)
      
      # Alice encrypts the message using her private key and Bob's public key
      a_shared_secret = computeSharedSecret(a_private_key, b_public_key)
      e = encryptMessage(a_shared_secret, msg)
      
      # Bob decrypts the message using his private key and Alice's public key
      b_shared_secret = computeSharedSecret(b_private_key, a_public_key)
      answer = decryptMessage(b_shared_secret, e)
      
      error = error or a_shared_secret != b_shared_secret or answer != msg
      if a_shared_secret != b_shared_secret:
         print("FAILURE: shared secret different")
         error = True
      elif answer != msg:
         print("FAILURE: on encryption. Size: {}, Message: #{}#, Answer: #{}#".format(size, msg, answer))
         
   if not error:
      print("SUCESS")
   
def testKeySerialization():
   keyGenerator = createKeyGenerator()
   error = False
   
   for _ in range(10000):
      size = randrange(10, 256)
      msg = createRandomMessage(size)
      
      a_private_key, a_public_key = generateKeys(keyGenerator)
      b_private_key, b_public_key = generateKeys(keyGenerator)
      
      # Alice encrypts the message using her private key and Bob's public key
      a_shared_secret = computeSharedSecret(a_private_key, b_public_key)
      e = encryptMessage(a_shared_secret, msg)

      # Serialize and deserialize Alice's public key
      b_public_key_serialized = serializePublicKey(b_public_key)
      b_public_key = deserializePublicKey(b_public_key_serialized)
      
      # Decrypt the message using the key after serialization
      a_shared_secret = computeSharedSecret(a_private_key, b_public_key)
      answer = decryptMessage(a_shared_secret, e)
      
      if msg != answer:
         print("FAILURE: on serialization. Size: {}, Message: #{}#, Answer: #{}#".format(size, msg, answer))
         error = True
            
   if not error:
      print("SUCESS")