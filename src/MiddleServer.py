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

      # We need to spawn off a thread here, else we will block
      # the entire program
      threading.Thread(target=self.setupConnection, args=()).start()
 
      # Setup main listening socket to accept incoming connections
      threading.Thread(target=self.listen, args=()).start()
      
      # Used during for onion rotuing in the conversational protocol  
      # TODO: make this a dict{ clientIp: key }
      # The key will be updated each time a message from that client is received.
      self.clientLocalKey = ""
      
      # The server keys
      self.__privateKey, self.publicKey = TU.generateKeys( 
            TU.createKeyGenerator() )

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
      self.listenSock.bind(('localhost', self.localPort))
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
      clientData = conn.recv(4096).decode("utf-8")

      # Format as message
      clientMsg = Message()
      clientMsg.loadFromString(clientData)

      # Check if the packet is for setting up a connection
      if clientMsg.getNetInfo() == 0:
         # If it is, add the previous server's IP and Port
         self.previousServerIP = client_addr[0]
         self.previousServerPort = int(clientMsg.getPayload())
         conn.close()
      elif clientMsg.getNetInfo() == 1: 
         # In here, we handle packets being sent towards
         # the dead drop. There is only one way to send packets
         
         # Onion routing stuff
         newPayload = TU.encryptOnionLayer(self.__privateKey, 
                                           self.clientLocalKey, 
                                           clientMsg.getPayload())
         clientMsg.setPayload(newPayload)
         
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((self.nextServerIP, self.nextServerPort))
         sock.sendall(str.encode(str(clientMsg)))
         sock.close()
      elif clientMsg.getNetInfo() == 2: 
         # In here, we are handling messages send back
         # to the client. There is only one way to send packets
         
         # Onion routing stuff
         newPayload = TU.encryptOnionLayer(self.__privateKey, 
                                           self.clientLocalKey, 
                                           clientMsg.getPayload())
         clientMsg.setPayload(newPayload)
         
         tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         tempSock.connect((self.previousServerIP,self.previousServerPort))
         tempSock.sendall(str.encode(str(clientMsg)))
         tempSock.close()
