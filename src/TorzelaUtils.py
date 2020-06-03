#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization

from random import randrange, shuffle

from string import ascii_letters
from random import choice

def createRandomMessage(messageSize):
   chars = ascii_letters + ".,:;-+*/?!()[]{}"
   return ''.join(choice(chars) for i in range(messageSize))

def createKeyGenerator():
   p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
   g = 2
   params_numbers = dh.DHParameterNumbers(p,g)
   parameters = params_numbers.parameters(default_backend())
   return parameters

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

# Given a RSA public key, returns its serialization as a string
   # This is for testing. We should never send a private key over the network
def serializePublicKey(public_key):
   return public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
   ).decode()

# Given a string representing a RSA public key, 
# returns a public key object
# This is for testing. We should never send a private key over the network
def deserializePublicKey(public_key):
   return serialization.load_pem_public_key(public_key.encode(), 
                                            backend=default_backend())
   
# Given a RSA private key, returns its serialization as a string
def serializePrivateKey(privateKey):
   return privateKey.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
   ).decode()

# Given a string representing a RSA private key, 
# returns a private key object
def deserializePrivateKey(privateKey):
   return serialization.load_pem_private_key(privateKey.encode(),
                                             password=None,
                                             backend=default_backend())
   
# Decrypts one layer of the onion routing. This is used by the servers.
# Takes an private key object (serverPrivateKey) and a string (msgPayload).
# serverType is an int. It dictates the form of the msgPayload after 
# decoding it:
# 0 -> FrontServers and MiddleServers. decodedMsgPayload = "nest_pk#payload"
#     In this case, it returns (ppk, payload="nest_pk#payload")
# 1 -> SpreadingServers. decodedMsgPayload = "DDS#next_pk#payload"
#     In this case, it returns (ppk, DDS, payload="next_pk#payload")
#     Where DDS is the index of the deadropServer where the msg must be sent
# 2 -> DeadDropServer. decodedMsgPayload = "clientChain#DD#payload"
#     In this case, it returns (ppk, clientChain, DD, payload)
#     Where clientChain is the chain where the response must be sent back
#     And DD is the deadDrop
# payload is a string, the rest of returned arguments are intergers or keys
def decryptOnionLayer(serverPrivateKey, msgPayload, serverType):
   ppk, payload = msgPayload.split("#", maxsplit=1)
   ppk = deserializePublicKey(ppk)
   payload = payload.encode("latin_1")
   sharedSecret = computeSharedSecret(serverPrivateKey, ppk)
   decryptedPayload = decryptMessage(sharedSecret, payload)
      
   if serverType == 0:
      return ppk, decryptedPayload    
   elif serverType == 1:
      DDS, next_ppk, payload = decryptedPayload.split("#", maxsplit=2)
      decryptedPayload = "{}#{}".format(next_ppk, payload)         
      return int(DDS), ppk, decryptedPayload
   elif serverType == 2:
      clientChain, DD, payload = decryptedPayload.split("#", maxsplit=2)
      return ppk, int(clientChain), int(DD), payload
   else:
      print("ERROR decryptOnionLayer: serverType must be in {0,1,2}")

# Encrypts a single onion layer. Returns a string.
def encryptOnionLayer(serverPrivateKey, clientPublicKey, msgPayload):
   sharedSecret = computeSharedSecret(serverPrivateKey, clientPublicKey)
   encryptedPayload = encryptMessage(sharedSecret, msgPayload)
   return encryptedPayload.decode("latin_1")

# Apply onion routing. On each layer the message looks like this:
# "serialized_pk#encrypted_data"
def applyOnionRouting(localKeys, chainServersPublicKeys, data):
      localKeys.reverse()
      chainServersPublicKeys.reverse()
      for local_keys, server_pk in zip (localKeys, chainServersPublicKeys):
         local_sk, local_pk = local_keys
         sharedSecret = computeSharedSecret(local_sk, server_pk)
         data = encryptMessage(sharedSecret, data)
         serialized_local_pk = serializePublicKey(local_pk)
         data = "{}#{}".format(serialized_local_pk, data.decode("latin_1"))
         
      chainServersPublicKeys.reverse()
      return data

# Warning: This is not the most secure way to create a random permutation.
# For real deployment, a different way to generate this permutation should
# be implemented. This is beyond the scope of this project. Mpre information:
# https://docs.python.org/3/library/random.html
def generatePermutation(n):
   l = list(range(n))
   shuffle(l)
   return (l)
   
# Shuffles the elements in the array toShuffle following the given permutation
def shuffleWithPermutation(toShuffle, permutation):
   if len(toShuffle) != len(permutation): 
      print("Error while shuffling. The size of the permutation and" + 
            "the number of elements to shuffle must be the same")
      return (-1)
   
   shuffled = [ 0 for _ in range(len(permutation)) ]
   for i, msg in zip(permutation, toShuffle):
      shuffled[i] = msg
      
   return shuffled

# Unshuffles the messages following the given permutation
def unshuffleWithPermutation(toShuffle, permutation):
   if len(toShuffle) != len(permutation): 
      print("Error unshuffling messages. The size of the permutation and" + 
            "the number of messages must be the same")
      return (-1)
   
   unshuffled = []
   for i in permutation:
      unshuffled.append( toShuffle[i] )
      
   return unshuffled
      
def testShuffling():
   error = False
   for _ in range(1, 100):
      size = randrange(10**3, 10**5)
      
      # For testing we just shuffle numbers instead of messages
      messages = generatePermutation(size)
      
      perm = generatePermutation(size)
      shuffledMessages = shuffleWithPermutation(messages, perm)
      unshuffledMessages = unshuffleWithPermutation(shuffledMessages, perm)
      
      if messages != unshuffledMessages:
         print("FAILURE.\nBefore:{}\nAfter: {}".format(messages, unshuffledMessages))
         error = True
   if not error:
      print("SUCESS")

def testEncryption():
   
   keyGenerator = createKeyGenerator()
   
   error = False
   
   for _ in range(1, 1000):
         
      a_private_key, a_public_key = generateKeys(keyGenerator)
      b_private_key, b_public_key = generateKeys(keyGenerator)
      
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
         error = True
         
   if not error:
      print("SUCESS")
      
def testKeySerialization():
   error = False
   
   for _ in range(10000):
      size = randrange(10, 256)
      msg = createRandomMessage(size)
      
      a_private_key, a_public_key = generateKeys(createKeyGenerator())
      b_private_key, b_public_key = generateKeys(createKeyGenerator())
      
      # Alice encrypts the message using her private key and Bob's public key
      a_shared_secret = computeSharedSecret(a_private_key, b_public_key)
      e = encryptMessage(a_shared_secret, msg)

      # Serialize and deserialize Bob's public key
      a_public_key_serialized = serializePublicKey(a_public_key)
      a_public_key = deserializePublicKey(a_public_key_serialized)
      
      # Decrypt the message using the key after serialization
      b_shared_secret = computeSharedSecret(b_private_key, a_public_key)
      answer = decryptMessage(b_shared_secret, e)
      
      if msg != answer:
         print("FAILURE: on serialization. Size: {}, Message: #{}#, Answer: #{}#".format(size, msg, answer))
         error = True
            
   if not error:
      print("SUCESS")
      
   
   
def testAsync():
   import asyncio
   import time
   import threading
   import logging
   
   def goaaaaa(i, lock):
      logging.info("goaaaa")
      print("gaaaao", flush=True)
      with (yield from lock):
         logging.info(i)
         time.sleep(1)
         logging.info(i)
      
         
   lock = asyncio.Lock()
   
   threading.Thread(target=goaaaaa, args=(1, lock,)).start()
   threading.Thread(target=goaaaaa, args=(3, lock,)).start()
   threading.Thread(target=goaaaaa, args=(5, lock,)).start()
   time.sleep(10)
   print("go")
   # t1.join()
   # t2.join()
   # t3.join()
      
         
   
   