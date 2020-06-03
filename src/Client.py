#!/usr/bin/env python3

import socket
import threading
import time
import sys
from message import Message
import TorzelaUtils as TU
import queue
import pickle

class Client:   
   # Configure the client with the IP and Port of the next server
   def __init__(self, serverIP, serverPort, localPort, client_name=None):
      # serverIP and serverPort is the IP and port of the next
      # server in the chain
      self.serverIP = serverIP
      self.serverPort = serverPort
      self.client_name = client_name

      # When getting a response from the network, this client
      # will listen on this port
      self.localPort = localPort
      
      # Queue of messages that will be sent to the Front Server, one per round
      self.messagesQueue = queue.Queue()
  
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
      # For now, set them manually during the test setup
      
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
      self.partnerPublicKeys = []
      
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
      setupMsg.setPayload("{}|{}|{}".format(self.localPort, serializedKey, self.client_name))
 
      self.connectionMade = False
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # While we have not been able to connect to the next server
      # in the chain...
      while not self.connectionMade:
         try:
            # Try to connect and send it our setup message
            self.sock.connect((self.serverIP, self.serverPort))
            self.sock.sendall(str.encode(str(setupMsg)))
            
            # Read/Set server pks
            lock = threading.Lock()
            try:
               buffer = self.sock.recv(32768)
               lock.acquire()
               pks = pickle.loads(buffer)
               self.chainServersPublicKeys = [TU.deserializePublicKey(pk) for pk in pks['chain_pks']]
               self.deadDropServersPublicKeys = [TU.deserializePublicKey(pk) for pk in pks['dead_drop_pks']]
            except Exception as e:
               print(e)
            finally:
               lock.release()

            self.connectionMade = True
         except:
            # Just keep trying to connect...
            # Add a delay here so we don't consume a 
            # lot of CPU time
            time.sleep(1)
      print("Client successfully connected!")
      # Close the connection after we verify everything is working
      self.sock.close()

      # Create the listening socket
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.bind(('localhost', self.localPort))

      # Wait for a round to start, a message will be sent by the Front Server
      while True:
         self.sock.listen(1) # listen for 1 connection
         conn, server_addr = self.sock.accept()
         recvStr = conn.recv(32768).decode("utf-8")
         
         print("Client got " + recvStr)
         
         msg = Message()
         msg.loadFromString(recvStr)
         
         # New Potential Partner Joined Network
         if msg.getNetInfo() == 10:
            data = msg.getPayload()
            print(data)
            print(type(data))

            data = pickle.loads(unicode(data, 'utf-8'))
            print(data)
            print(type(data))
            new_client_name, new_client_pk, new_client_port = data['client_name'], TU.deserializePublicKey(data['client_pk']), data['client_port']
            print(f'{new_client_name} joined the Torzela gang')
            self.partnerPublicKeys.append((new_client_name, new_client_pk, new_client_port))
         # new invitation
         elif msg.getNetInfo() == 11:
            data = msg.getPayload()
            partner_name = data.split(':')[1]
            for partner in self.partnerPublicKeys:
               if partner[0] == partner_name:
                  self.partnerPublicKey = partner[1]
                  continue
         elif msg.getNetInfo() != 5:
            print("Client error: waiting for round to start but received" +
                  " a different type of message")
         else: 
            # Message From Active Conversation
            response = self.sendAndRecvMsg()
            if response.getPayload() != "":
               print("Client received: {}".format(response.getPayload()))
            else:
               print("Client received empty message")
            
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
         print('Client: Fake Partner')
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
   # Should ONLY be called after a message from the Front Server stating that
   # a new round just started
   def sendAndRecvMsg(self):
      # If the initial setup has not gone through,
      # then just block and wait. We can't send anything
      # before we know the network is up and working
      while not self.connectionMade:
         time.sleep(1)
         
      # If we don't have messages to send, create a new empty one
      if self.messagesQueue.qsize() == 0:
         self.newMessage("")
      payload = self.messagesQueue.get()
      msg = Message()
      msg.setPayload(payload)
      
      # Prepare the payload following the conversational protocol
      msg.setPayload( self.preparePayload(msg.getPayload()) )
      
      # This 1 means we are sending the message towards a dead drop 
      msg.setNetInfo(1)

      # Connect to next server
      tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      tempSock.connect((self.serverIP, self.serverPort))

      # Send our message to the server
      tempSock.sendall(str(msg).encode("utf-8"))
      tempSock.close()

      # Listen for a response
      self.sock.listen(1)
      conn, server_addr = self.sock.accept()
      # All messages are fixed to 32K
      recvStr = conn.recv(32768).decode("utf-8")
      conn.close()

      print(recvStr)
      
      # Convert response to message
      m = Message()
      m.loadFromString(recvStr)
      
      # Undo onion routing to the payload
      if self.partnerPublicKey != "": 
         m.setPayload( self.decryptPayload(m.getPayload()) )
      else:
         m.setPayload("")
         
      return m

   # Temporarily just ping
   def dial(self, client_name):
      for partner in self.partnerPublicKeys:
         if partner[0] == client_name:
            self.partnerPublicKey = partner[1]
            # Connect to next server
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tempSock.connect(('', partner[2]))
            message = Message()
            message.setPayload(f'Invitation from:{self.client_name}')
            message.setNetInfo('11')
            # Send our message to the server
            tempSock.sendall(str(message).encode("utf-8"))
            tempSock.close()
            break
      
   
   def new_dial(self, recipient_public_key):
      """
      Handle Dialing Protocol/ Invitation
      Dialing Protocol
      1. How Dialing is Facilitated?
         1. Dialing Facilitated in Rounds every 10 minutes
         2. For each dialing round we create N invitation deaddrops
               Each user is designated an invitation deaddrop via pk
      2. How to Dial a User
         1. UserA dials UserB by placing a message into UserB's invitation deaddrop
            1. Invitation deaddrop assigned at the beginning of the round
            2. Message Contents = sender's pk, nonce, and MAC encrypted w/ recipient's pk
         2. All Users periodicallally poll their assigned invitation dead drop to checksfor invitations
      """
      
      # If the initial setup has not gone through,
      # then just block and wait. We can't send anything
      # before we know the network is up and working
      while not self.connectionMade:
         time.sleep(1)
      print('Dialing')
      # Connect to next server
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.connect((self.serverIP, self.serverPort))

      message = Message()
      message.setPayload("User Invitation")

      # Set the user to receive the invitation
      self.partnerPublicKey = recipient_public_key
      data = self.preparePayload(message.getPayload())
      message.setPayload(data)

      # Send our message to the deaddrop; 3 Indicates we are initiating a conversation via dialing protocol
      message.setNetInfo(3)
      self.sock.sendall(str(message).encode("utf-8"))
      self.sock.close()

      return
   
   def download_invitations(self, invitationDeadDropPort, potential_partner_pks):
      while True:
         time.sleep(10)
         self.invitationDeadDropPort = invitationDeadDropPort
         dial_message = Message()
         dial_message.setNetInfo(6)
         dial_message.setPayload("{}|{}".format(self.localPort, TU.serializePublicKey(self.publicKey)))
   
         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         while True:
            try:
               self.sock.connect(('', self.invitationDeadDropPort))
               self.sock.sendall(str.encode(str(dial_message)))
               break
            except:
               time.sleep(1)

         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         self.sock.bind(('localhost', self.localPort))
         self.sock.listen(1) # listen for 1 connection
         conn, server_addr = self.sock.accept()
         # All messages are fixed to 4K
         data = conn.recv(32768).decode("utf-8")

         data = data.encode('latin_1')

         m = Message()
         for potential_partner_pk in potential_partner_pks:
            try:
               sharedSecret = TU.computeSharedSecret(self.__privateKey, potential_partner_pk)
               data = TU.decryptMessage(sharedSecret, data)
               m.setPayload(data)
            except:
               pass

         return m

   # Receives a string, adds a new message with the given payload to the
   # queue of messages that will be sent to the Front Server
   def newMessage(self, payload):
      self.messagesQueue.put(payload)


   def get_private(self):
      return self.__privateKey
