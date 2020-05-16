#!/usr/bin/env python3

import socket
import threading
import time
from message import Message

# For the encryption
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Client:
    
   # Generate a pair of public and private keys
   def generateKeys(self):
      privateKey = self.keyGenerator.generate_private_key()
      publicKey = privateKey.public_key()
      return privateKey, publicKey
   
   # Configure the client with the IP and Port of the next server
   def __init__(self, serverIP, serverPort, localPort):
      # serverIP and serverPort is the IP and port of the next
      # server in the chain
      self.serverIP = serverIP
      self.serverPort = serverPort

      # When getting a response from the network, this client
      # will listen on this port
      self.localPort = localPort
  
      # Will be used to create multiple key when sending each message
      self.keyGenerator = dh.generate_parameters(generator=2, key_size=512, 
                                                 backend=default_backend())
   
      # The client keys
      self.private, self.publicKey = self.generateKeys()

      # We need to spawn off a thread here, else we will block the
      # entire program (i.e. if we create the client then the server
      # in our python program, the client will block and wait for
      # the server to come up...but that can't happen until the
      # client is done configuring, so we would end up with deadlock)
      threading.Thread(target=self.setupConnection, args=()).start()
      
      # The chain this client belongs to. It is provided by the Front
      # Server after the first connection.
      self.myChain = -1
      
      # The public keys from the n-1 servers in your chain.
      # Index 0 is the Front Server will index n-2 (the last one) is
      # the Spreading Server. These are provided by the Front Server 
      # after the first connection
      self.chainServersPublicKeys = []
      
      # The public keys from all the Dead Drops Servers.
      self.deadDropServersPublicKeys = []
   
      # The size of the messages. This value is provided by the Front Server
      # Warning: this value must be multiple of block_size used in the
      # encryption/dercyption, currently set to 16
      self.messageSize = 256
      
      # TODO: myChain, messageSize and the server keys must be obtained from the Front Server

   def setupConnection(self):
      # Connect to the next server to give it our listening port
      # and public key. The server will also be able to tell our ip
      # address just by receiving a connection from us
      # This is the setup message below that will hold this information
      setupMsg = Message()
      setupMsg.setNetInfo(0)
      setupMsg.setPayload("{}|{}".format(self.localPort, self.publicKey))
 
      self.connectionMade = False
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # While we have not been able to connect to the next server
      # in the chain...
      while not self.connectionMade:
         try:
            # Try to connect and send it our setup message
            self.sock.connect((self.serverIP, self.serverPort))
            self.sock.sendall(str.encode(str(setupMsg)))
            self.connectionMade = True
         except:
            # Just keep trying to connect...
            # Add a delay here so we don't consume a 
            # lot of CPU time
            time.sleep(1)
      print("Client successfully connected!")
      # Close the connection after we verify everything is working
      self.sock.close()


   # Send and receive a message from Torzela
   # Because we always receive a response, it doesn't
   # make sense to have two separate send and receive methods
   def sendAndRecvMsg(self, msg):
      # If the initial setup has not gone through,
      # then just block and wait. We can't send anything
      # before we know the network is up and working
      while not self.connectionMade:
         time.sleep(1)

      # Connect to next server
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.connect((self.serverIP, self.serverPort))

      # Send our message to the server
      # the 1 means we are sending the message towards
      # a dead drop 
      msg.setNetInfo(1)
      self.sock.sendall(str.encode(str(msg)))
      self.sock.close()

      # Now open up the listening port to listen for a response
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.bind(('localhost', self.localPort))
      self.sock.listen(1) # listen for 1 connection
      conn, server_addr = self.sock.accept()
      # All messages are fixed to 4K
      recvStr = conn.recv(4096)
      conn.close()

      # Convert response to message and return it
      m = Message()
      m.loadFromString(recvStr)
      
      return m
   
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
   def encryptMessage(sharedSecret, msg):
      # TODO: fix msg size to 256. Give an error if len(msg) > msg_size
      block_size = 16
      iv = os.urandom(block_size)
      cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=backend)
      encryptor = cipher.encryptor()
      return encryptor.update(msg.encode()) + encryptor.finalize()
      
   # Decrypt the message using symmetric encryption.
   # sharedSecret is the shared secret and msg is an array of bytes containing
   # the encrypted message. Returns a string
   def decryptMessage(sharedSecret, msg):
      # TODO: fix msg size to 256. Give an error if len(msg) > msg_size
      block_size = 16
      iv = os.urandom(block_size)
      cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=backend)
      decryptor = cipher.decryptor()
      return decryptor.update(ct) + decryptor.finalize()
   

# Key generator

parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

a_private_key = parameters.generate_private_key()
a_peer_public_key = a_private_key.public_key()

b_private_key = parameters.generate_private_key()
b_peer_public_key = b_private_key.public_key()

a_shared_key = a_private_key.exchange(b_peer_public_key)
b_shared_key = b_private_key.exchange(a_peer_public_key)

derived_key = HKDF(
      algorithm=hashes.SHA256(),
      length=32,
      salt=None,
      info=b'handshake data',
      backend=default_backend()
   ).derive(a_shared_key)      

msg = "16 chars msg...."


backend = default_backend()
# the msg must be multiple of block_size
block_size = 16
iv = os.urandom(block_size)
cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
ct = encryptor.update(msg.encode()) + encryptor.finalize()
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize()
      

      
      
      
      
      
      
