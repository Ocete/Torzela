#!/usr/bin/env python3

import socket
import threading
import time
import sys
from message import Message
import TorzelaUtils as TU

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
      self.__privateKey, self.publicKey = TU.generateKeys(self.keyGenerator)

      # We need to spawn off a thread here, else we will block the
      # entire program (i.e. if we create the client then the server
      # in our python program, the client will block and wait for
      # the server to come up...but that can't happen until the
      # client is done configuring, so we would end up with deadlock)
      threading.Thread(target=self.setupConnection, args=()).start()
      
      # TODO: We get to know this key through the Dialing Protocol
      self.partnerPublicKey = ""
      
      # Temporary keys. They are computed for each sent message.
      self.temporaryKeys = []
      
      # TODO: All the following values must be obtained from the Front Server
      
      # The chain this client belongs to. It is provided by the Front
      # Server after the first connection.
      self.myChain = 0
      
      # number of dead drops and dead drop servers
      self.nDD = 2**128
      self.nDDS = 1
      
      # The conversational round we are currently in
      self.round = 1
      
      # The public keys from the n-1 servers in your chain.
      # Index 0 is the Front Server will index n-2 (the last one) is
      # the Spreading Server. These are provided by the Front Server 
      # after the first connection
      self.chainServersPublicKeys = []
      
      # The public keys from all the Dead Drops Servers.
      self.deadDropServersPublicKeys = []
      
      # An integer in [0, self.nDDS), index of the dead drop server.
      # It's computed in every round by the client
      self.deadDropServerIndex = 0

      self.invitationDeadDropPort = None

   def setupConnection(self):
      # Connect to the next server to give it our listening port
      # and public key. The server will also be able to tell our ip
      # address just by receiving a connection from us
      # This is the setup message below that will hold this information
      setupMsg = Message()
      setupMsg.setNetInfo(0)
      serializedKey = TU.serializePublicKey(self.publicKey)
      setupMsg.setPayload("{}|{}".format(self.localPort, serializedKey))
 
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

   # Returns the dead drop chosen and the dead drop server where it's located.
   def computeDeadDrop(self, sharedSecret):
      aux = int.from_bytes(sharedSecret, 
                           byteorder=sys.byteorder) * (self.round + 1)
      deadDrop = aux % self.nDD
      deadDropServer = deadDrop % self.nDDS
      return deadDrop, deadDropServer

   # Creates a pair (sk, pk) for each server in the chain + the dead drop server.
   def generateTemporaryKeys(self):
      self.temporaryKeys = []
      for _ in range( len(self.chainServersPublicKeys) + 1):
         self.temporaryKeys.append( TU.generateKeys(self.keyGenerator) )

   # Applies onion routing to the messages and fits in it all the information
   # needed for the servers. data must be a string with the content of the 
   # message and round an integer. Returns a string
   def preparePayload(self, data):
      self.generateTemporaryKeys()
      
      ppk = self.partnerPublicKey
      # If we are not currently talking to anyone, create a fake message
      # and a fake reciever
      if self.partnerPublicKey == "":
         _, ppk = TU.generateKeys(self.keyGenerator)
         data = TU.createRandomMessage(32)
      
      # Compute the message for your partner   
      sharedSecret = TU.computeSharedSecret(self.__privateKey, ppk)
      deadDrop, self.deadDropServerIndex = self.computeDeadDrop(sharedSecret)
      data = TU.encryptMessage(sharedSecret, data)
      
      # Compute the message for the Dead Drop Server. It includes how to 
      # send it back (the chain) and the dead drop.
      # It has the following form: 
      # Before encryption: "myChain#deadDrop#data"
      # After encryption: "deadDropServer#serialized_pk#encrypted_data"
      data = "{}#{}#{}".format(self.myChain, deadDrop, data.decode("latin_1"))
      server_pk = self.deadDropServersPublicKeys[self.deadDropServerIndex]
      local_sk, local_pk = self.temporaryKeys[-1]
      sharedSecret = TU.computeSharedSecret(local_sk, server_pk)  
      data = TU.encryptMessage(sharedSecret, data)
      serialized_local_pk = TU.serializePublicKey(local_pk)
      data = "{}#{}#{}".format(self.deadDropServerIndex, serialized_local_pk,
                               data.decode("latin_1"))
      # Next step:
      # Apply onion routing
      data = TU.applyOnionRouting(self.temporaryKeys[:-1], 
                                  self.chainServersPublicKeys,
                                  data)
      
      return data
   
   # data is a string containing the received message payload. Undo onion 
   # routing to obtain the decrypted message. Returns a string.
   def decryptPayload(self, data):
      data = data.encode("latin_1")
      
      # Undo the onion routing
      for local_keys, server_pk in zip (self.temporaryKeys[:-1], 
                                        self.chainServersPublicKeys):
         local_sk, local_pk = local_keys
         sharedSecret = TU.computeSharedSecret(local_sk, server_pk)
         data = TU.decryptMessage(sharedSecret, data).encode("latin_1")
         
      # The dead drop encryption layer 
      local_sk, local_pk = self.temporaryKeys[-1]
      server_pk = self.deadDropServersPublicKeys[self.deadDropServerIndex]
      sharedSecret = TU.computeSharedSecret(local_sk, server_pk)
      data = TU.decryptMessage(sharedSecret, data).encode("latin_1")
         
      # Last layer of encryption includes how your partner encrypted it.
      sharedSecret = TU.computeSharedSecret(self.__privateKey, 
                                            self.partnerPublicKey)
      data = TU.decryptMessage(sharedSecret, data)
      
      return data
   
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

      # Prepare the payload following the conversational protocol
      msg.setPayload( self.preparePayload(msg.getPayload()) )

      # Send our message to the server
      # the 1 means we are sending the message towards
      # a dead drop 
      msg.setNetInfo(1)
      self.sock.sendall(str(msg).encode("utf-8"))
      self.sock.close()

      # Now open up the listening port to listen for a response
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.bind(('localhost', self.localPort))
      self.sock.listen(1) # listen for 1 connection
      conn, server_addr = self.sock.accept()
      # All messages are fixed to 4K
      recvStr = conn.recv(32768).decode("utf-8")
      conn.close()

      # Convert response to message
      m = Message()
      m.loadFromString(recvStr)
      
      # Undo onion routing to the payload
      if self.partnerPublicKey != "": 
         m.setPayload( self.decryptPayload(m.getPayload()) )
      
      return m
   # Note: Skyler Implementation Inspired by Jose's Conversation Protocol
   def dial(self, recipient_public_key, invitationDeadDropPort):
      print('connection not made')
      # If the initial setup has not gone through,
      # then just block and wait. We can't send anything
      # before we know the network is up and working
      while not self.connectionMade:
         time.sleep(1)
      print('Dialing')
      # Connect to next server
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.connect((self.serverIP, self.serverPort))

      # Prepare the payload following the conversational protocol
      message = Message()
      self.generateTemporaryKeys()

      # Create shared secret using both the sender secret key and recipient's public key
      shared_secret = TU.computeSharedSecret(self.__privateKey, recipient_public_key)
      dead_drop, self.deadDropServerIndex = self.computeDeadDrop(shared_secret)
      data = TU.encryptMessage(shared_secret, f"User Invitation")

      # Compute the message for the Dead Drop Server. It includes how to 
      # send it back (the chain) and the dead drop.
      # It has the following form: 
      # Before encryption: "myChain#deadDrop#data"
      # After encryption: "deadDropServer#serialized_pk#encrypted_data"
      data = "{}#{}#{}".format(self.myChain, dead_drop, data.decode("latin_1"))
      server_pk = self.deadDropServersPublicKeys[self.deadDropServerIndex]
      local_sk, local_pk = self.temporaryKeys[-1]
      sharedSecret = TU.computeSharedSecret(local_sk, server_pk)  
      data = TU.encryptMessage(sharedSecret, data)
      serialized_local_pk = TU.serializePublicKey(local_pk)
      data = "{}#{}#{}".format(self.deadDropServerIndex, serialized_local_pk,
                               data.decode("latin_1"))
      # Next step:
      # Apply onion routing
      data = TU.applyOnionRouting(self.temporaryKeys[:-1], 
                                  self.chainServersPublicKeys,
                                  data)
      
      # Prepare the payload following the conversational protocol
      message.setPayload(data)

      # Send our message to the deaddrop; 3 Indicates we are initiating a conversation via dialing protocol
      message.setNetInfo(3)
      self.sock.sendall(str(message).encode("utf-8"))
      self.sock.close()

      return None
   
   def set_invitation_dead_drop(self, invitationDeadDropPort: str):
      self.invitationDeadDropPort = invitationDeadDropPort
      # Now open up the listening port to listen for a response
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      print('listening invitationdead', str(self.localPort))
      self.sock.bind(('localhost', self.localPort))
      self.sock.listen(2) # listen for 1 connection
      conn, server_addr = self.sock.accept()
      print(server_addr)
      # All messages are fixed to 4K
      recvStr = conn.recv(32768).decode("utf-8")
      conn.close()

      # Convert response to message
      m = Message()
      m.loadFromString(recvStr)
      
      sharedSecret = TU.computeSharedSecret(self.__privateKey, 
                                            self.partnerPublicKey)
      m.setPayload(TU.decryptMessage(sharedSecret, m.getPayload()))

      return m
