#!/usr/bin/env python3

import socket
import threading
import time
from message import Message
import TorzelaUtils as TU

class SpreadingServer:
   # nextServers is an array of tuples in the form
   #  (<IP>, <Port>)
   # where <IP> is the IP address of a Dead Drop and
   # <Port> is the port that the Dead Drop is listening on
   def __init__(self, nextServers, localPort):
      self.nextServers = nextServers
      self.localPort = localPort

      # We only allow one connect to the SpreadingServer
      # Initialize these to 0 here, we will set them
      # later when we get the initial connection
      self.previousServerIP = 0
      self.previousServerPort = 0

      # We need to wait for all connections to setup, so create
      # an integer and initialize it with the number of dead drops
      # we are connecting to. Every time we successfully connect to
      # one, decrement this value. When it is equal to 0, we know 
      # all of the connections are good
      self.allConnectionsGood = len(nextServers)
      for ddServer in nextServers:
         # We need to spawn off a thread here, else we will block
         # the entire program.
         threading.Thread(target=self.setupConnection, args=(ddServer,)).start()
 
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

   def setupConnection(self, ddServer):
      # Before we can connect to the next server, we need
      # to send a setup message to the next server
      setupMsg = Message()
      setupMsg.setType(0)
      setupMsg.setPayload("{}".format(self.localPort))

      connectionMade = False
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      while not connectionMade:
         try:
            sock.connect(ddServer)
            sock.sendall(str.encode(str(setupMsg)))
            connectionMade = True
            # When self.allConnectionsGood is 0, we know all of 
            # the connections have been setup properly
            self.allConnectionsGood -= 1
         except:
            # Put a delay here so we don't burn CPU time
            time.sleep(1)
      sock.close()


   # This is where all incoming messages are handled
   def listen(self):
      # Wait until we have connected to the next server
      while self.allConnectionsGood != 0:
         time.sleep(1)

      # Listen for incoming connections
      self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.listenSock.bind(('localhost', self.localPort))
      self.listenSock.listen(10)
   
      while True:
         print("SpreadingServer awaiting connection")
         conn, client_addr = self.listenSock.accept()

         print("SpreadingServer accepted connection from " + str(client_addr))

         # Spawn a thread to handle the client
         threading.Thread(target=self.handleMsg, args=(conn, client_addr,)).start()
   
   # This runs in a thread and handles messages from clients
   def handleMsg(self, conn, client_addr):
      # Receive data from client
      clientData = conn.recv(4096).decode("utf-8")

      # Format as message
      clientMsg = Message()
      clientMsg.loadFromString(clientData)

      print("Spreading Server got " + clientData)

      # Check if the packet is for setting up a connection
      if clientMsg.getNetInfo() == 0:
         # If it is, record it's IP and Port
         self.previousServerIP = client_addr[0]
         self.previousServerPort = int(clientMsg.getPayload())
         conn.close()
      elif clientMsg.getNetInfo() == 1: 
         # In here, we handle messages going from a client towards a dead drop
         # Send message to all dead drops
         
         # Onion routing stuff
         #self.clientLocalKey, deadDropServer, newPayload = TU.decryptOnionLayer(
         #      self.__privateKey, clientMsg.getPayload(), serverType=1)
         #clientMsg.setPayload(newPayload)
         
         # TODO (matthew): deadDropServer contains towards which server
         # the message has to be sent :D
         
         for ddrop in self.nextServers:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(ddrop)
            self.sock.sendall(str(clientMsg).encode("utf-8"))
            self.sock.close()
      elif clientMsg.getNetInfo() == 2: 
         # Here we handle messages coming from a dead drop back
         # towards a client. Just forward back to server
         
         # Onion routing stuff
         #newPayload = TU.encryptOnionLayer(self.__privateKey, 
         #                                  self.clientLocalKey, 
         #                                  clientMsg.getPayload())
         #clientMsg.setPayload(newPayload)
         
         tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         tempSock.connect((self.previousServerIP, self.previousServerPort))
         tempSock.sendall(str(clientMsg).encode("utf-8"))
         tempSock.close()
