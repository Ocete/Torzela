#!/usr/bin/env python3

import socket
import threading
import time
from message import Message
import TorzelaUtils as TU

class MiddleServer:
   # Set the next server's IP and listening port
   # also set listening port for this middle server
   def __init__(self, nextServerIP, nextServerPort, localPort):
      self.nextServerIP = nextServerIP
      self.nextServerPort = nextServerPort
      self.localPort = localPort

      # We can have a maximum of one server connected to us
      # Initialize these to 0 here, we will change them later
      # when we get the first connection
      self.previousServerIP = 0
      self.previousServerPort = 0

      # Used for onion rotuing in the conversational protocol  
      # The keys and messages will be updated each round
      self.clientLocalKeys = []
      self.clientMessages = []
      self.nMessages = 0
      
      # The server keys
      self.__privateKey, self.publicKey = TU.generateKeys( 
            TU.createKeyGenerator() )
      
      # We need to spawn off a thread here, else we will block
      # the entire program
      threading.Thread(target=self.setupConnection, args=()).start()
 
      # Setup main listening socket to accept incoming connections
      threading.Thread(target=self.listen, args=()).start()
      
   def getPublicKey(self):
      return self.publicKey

   def setupConnection(self):
      # Before we can connect to the next server, we need
      # to send a setup message to the next server
      setupMsg = Message()
      setupMsg.setType(0)
      setupMsg.setPayload("{}".format(self.localPort))

      self.connectionMade = False
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      while not self.connectionMade:
         try:
            sock.connect((self.nextServerIP, self.nextServerPort))
            sock.sendall(str.encode(str(setupMsg)))
            self.connectionMade = True
         except:
            # Put a delay here so we don't burn CPU time
            time.sleep(1)
      sock.close()
      print("MiddleServer successfully connected!")


   # This is where all messages are handled
   def listen(self):
      # Wait until we have connected to the next server
      while not self.connectionMade:
         time.sleep(1)

      # 1. Bind to localhost. We need to have the sock object
      #    available to other methods.
      self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.listenSock.bind(('', self.localPort))
      self.listenSock.listen(1)
   
      while True:
         print("MiddleServer awaiting connection")
         conn, client_addr = self.listenSock.accept()

         print("MiddleServer accepted connection from " + str(client_addr))

         # Spawn a thread to handle the client
         threading.Thread(target=self.handleMsg, args=(conn, client_addr,)).start()
   
   # This runs in a thread and handles messages from clients
   def handleMsg(self, conn, client_addr):
      # Receive data from client
      clientData = conn.recv(32768).decode("utf-8")

      # Format as message
      clientMsg = Message()
      clientMsg.loadFromString(clientData)
      
      print("Middle server got " + clientData)

      # Check if the packet is for setting up a connection
      if clientMsg.getNetInfo() == 0:
         # If it is, add the previous server's IP and Port
         self.previousServerIP = client_addr[0]
         self.previousServerPort = int(clientMsg.getPayload())
         conn.close()
      elif clientMsg.getNetInfo() == 1: 
         # In here, we handle packets being sent towards
         # the dead drop. There is only one way to send packets
         
         # TODO -> Add lock to this whole part
         
         if self.nMessages <= len(self.clientMessages):
            print("Middle server error: received more messages than expected")
         
         # Decrypt one layer of the onion message
         clientLocalKey, newPayload = TU.decryptOnionLayer(
               self.__privateKey, clientMsg.getPayload(), serverType=0)
         clientMsg.setPayload(newPayload)
         
         # Save the message data
         self.clientLocalKeys.append(clientLocalKey)
         self.clientMessages.append(clientMsg)
         
         if self.nMessages == len(self.clientMessages):
            self.forwardMessages()
         
      elif clientMsg.getNetInfo() == 2: 
         # In here, we are handling messages send back
         # to the client. There is only one way to send packets
         
         if self.nMessages <= len(self.clientMessages):
            print("Middle server error: received more messages than expected")
         
         # Encrypt one layer of the onion message
         clientLocalKey = self.clientLocalKeys[ len(self.clientMessages) ]
         newPayload = TU.encryptOnionLayer(self.__privateKey, 
                                           clientLocalKey, 
                                           clientMsg.getPayload())
         clientMsg.setPayload(newPayload)
         self.clientMessages.append(clientMsg)
         
         if self.nMessages == len(self.clientMessages):
            self.forwardResponses()
      elif clientMsg.getNetInfo() == 3: 
         # Dialing Protocol: Client -> DeadDrop
         
         _, newPayload = TU.decryptOnionLayer(
               self.__privateKey, clientMsg.getPayload(), serverType=0)
         clientMsg.setPayload(newPayload)
         
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((self.nextServerIP, self.nextServerPort))
         sock.sendall(str(clientMsg).encode("utf-8"))
         sock.close()
      elif clientMsg.getNetInfo() == 4: 
         # In here, we handle the first message sent by the previous server.
         # It notifies us of a new round and how many messages are coming
         
         # TODO -> Add lock to this whole part
         self.nMessages = int(clientMsg.getPayload())
         self.clientMessages = []
         self.clientLocalKeys = []
         
   # Assuming that the messages are stores in self.clientMessages this method
   # adds noise, shuffles the messages and forwards them to the next server
   def forwardMessages(self):
      
      # TODO (jose): Noise addition goes here
      
      # Apply the mixnet by shuffling the messages
      self.permutation = TU.generatePermutation(self.nMessages)
      shuffledMessages = TU.shuffleWithPermutation(self.clientMessages,
                                                   self.permutation)
      
      # Also shuffle the messages so they still match the clientMessages:
      # self.clientLocalKeys[ i ] is the key that unlocks message self.clientMessges[ i ]
      # This is used afterwards in handleMessage, getNetInfo() == 2
      self.clientLocalKeys = TU.shuffleWithPermutation(self.clientLocalKeys,
                                                         self.permutation)
      
      # Forward all the messages to the next server
      # Send a message to the next server notifying of the numbers of 
      # messages that will be sent
      firstMsg = Message()
      firstMsg.setNetInfo(4)
      firstMsg.setPayload("{}".format(self.nMessages))
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((self.nextServerIP, self.nextServerPort))
      sock.sendall(str(firstMsg).encode("utf-8"))
      sock.close()
      
      # Send all the messages to the next server
      for msg in shuffledMessages:
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((self.nextServerIP, self.nextServerPort))
         sock.sendall(str(msg).encode("utf-8"))
         sock.close()
      
      # Restart the messages so that we receive the responses from the 
      # next server
      self.clientMessages = []
      
   def forwardResponses(self):
      # Unshuffle the messages
      self.clientMessages = TU.unshuffleWithPermutation(self.clientMessages, 
                                                 self.permutation)
      
      # Send the responses back to the previous server
      for msg in self.clientMessages:
         tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         tempSock.connect((self.previousServerIP, self.previousServerPort))
         tempSock.sendall(str(msg).encode("utf-8"))
         tempSock.close()
         









