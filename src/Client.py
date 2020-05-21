#!/usr/bin/env python3

import socket
import threading
import time
import sys
from message import Message
import TorzelaUtils as TU

# For the encryption
class Client:   
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
      self.keyGenerator = TU.createKeyGenerator()
   
      # Create the client keys
      self.privateKey, self.publicKey = TU.generateKeys(self.keyGenerator)

      # We need to spawn off a thread here, else we will block the
      # entire program (i.e. if we create the client then the server
      # in our python program, the client will block and wait for
      # the server to come up...but that can't happen until the
      # client is done configuring, so we would end up with deadlock)
      threading.Thread(target=self.setupConnection, args=()).start()
      
      # TODO: We get to know this key through the Dialing Protocol
      self.partnerPublicKey = ""
      
      # TODO: All the following values must be obtained from the Front Server(?)
      
      # The chain this client belongs to. It is provided by the Front
      # Server after the first connection.
      self.myChain = -1
      
      # number of dead drops and dead drop servers
      self.nDD = 2**128
      self.nDDS = 1
      
      # The public keys from the n-1 servers in your chain.
      # Index 0 is the Front Server will index n-2 (the last one) is
      # the Spreading Server. These are provided by the Front Server 
      # after the first connection
      self.chainServersPublicKeys = []
      
      # The public keys from all the Dead Drops Servers.
      self.deadDropServersPublicKeys = []
      
      # Temporary keys. They are computed for each sent message.
      self.temporaryKeys = []
   
      # The size of the messages. This value is provided by the Front Server
      # Warning: this value must be multiple of block_size used in the
      # encryption/dercyption, currently set to 16
      self.messageSize = 256

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

   # Returns the dead drop chosen and the dead drop server where it's found.
   def computeDeadDrop(self, sharedSecret, round):
      aux = int.from_bytes(sharedSecret, byteorder=sys.byteorder) * round
      deadDrop = aux % self.nDD
      deadDropServer = deadDrop % self.nDDS
      return deadDrop, deadDropServer

   # Creates a pair (sk, pk) for each server in the chain + the dead drop server.
   def generateTemporaryKeys(self):
      self.temporaryKeys = []
      for _ in range( len(self.chainServersPublicKeys) + 1):
         self.temporaryKeys.append( TU.generateKeys(self.keyGenerator) )

   # Applies onion routing to the messages and fits in it all the information
   # needed for the servers. Returns a string
   def prepareMessage(self, msg, round):
      self.generateTemporaryKeys()
      
      ppk = self.partnerPublicKey
      # If we are not currently talking to anyone, create a fake message
      # and a fake reciever
      if self.partnerPublicKey == "":
         _, ppk = TU.generateKeys(self.keyGenerator)
         msg = TU.createRandomMessage(self.messageSize)
      
      # Compute the message for your partner   
      sharedSecret = TU.computeSharedSecret(self.privateKey, ppk)
      deadDrop, deadDropServer = self.computeDeadDrop(sharedSecret, round)
      msg = TU.encryptMessage(sharedSecret, msg)
      
      # Compute the message for the Dead Drop Server. It includes how to 
      # send it back (the chain) and the dead drop.
      # It has the following form: 
      # Before encryption: "myChain#deadDrop#msg"
      # After encryption: "deadDropServer#pk#encrypted_msg"
      msg = "{}#{}#{}".format(self.myChain, deadDrop, msg.decode("latin_1"))
      server_pk = self.deadDropServersPublicKeys[deadDropServer]
      local_keys = self.temporaryKeys[-1]
      sharedSecret = TU.computeSharedSecret(local_keys[0], server_pk)
      msg = TU.encryptMessage(sharedSecret, msg)
      msg = "{}#{}#{}".format(deadDropServer, local_keys[1], msg)
      
      return msg
   
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
      
