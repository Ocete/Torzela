#!/usr/bin/env python3

import socket
import threading
import asyncio
import time
from message import Message
import TorzelaUtils as TU

# Initialize a class specifically for the round info.
# This class will track if a round is currently ongoing or not, the
# actual identifying number of the round, the time it ended, and the lock 
# (so that no other messages are sent during the time of the round)
class RoundInfo:
   def __init__(self, newRound, endTime):
      self.open = True
      self.round = newRound
      self.endTime = endTime


class FrontServer:
   # Set the IP and Port of the next server. Also set the listening port
   # for incoming connections. The next server in the chain can
   # be a Middle Server or even a Spreading Server
   def __init__(self, nextServerIP, nextServerPort, localPort):
      self.nextServerIP = nextServerIP
      self.nextServerPort = nextServerPort
      self.localPort = localPort

      # Initialize round variables. This will allow us to track what
      # current round the server is on, in addition to the state that the
      # previous rounds are in
      self.roundID = 1
      self.rounds = {}
      self.lock = asyncio.Lock()

      # This will allow us to associate a client with it's public key
      # So that we can figure out which client should get which packet
      # Entries are in the form
      # ((<IP>,<Port>), <Public Key>)     (i.e. (('localhost', 80), "mykey") )
      # where <IP> is the client's IP address, <Port> is the client's
      # listening port, and <Public Key> is the client's public key
      self.clientList = []

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
      print("FrontServer successfully connected!")


   # This is where all messages are handled
   def listen(self):
      # Wait until we have connected to the next server
      while not self.connectionMade:
         time.sleep(1)

      # Listen for incoming connections
      self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.listenSock.bind(('localhost', self.localPort))
      self.listenSock.listen(10) # buffer 10 connections
   
      while True:
         print("FrontServer awaiting connection")
         conn, client_addr = self.listenSock.accept()

         # Continuously run a 2 second round, constantly updating as the
         # front server listens for incoming connections
         # To do this, we run the rounds in a separate thread
         roundDuration = 2
         print("Server on round: ", self.roundID)
         threading.Thread(target=self.runRound, args=(self.roundID, roundDuration)).start()

         print("FrontServer accepted connection from " + str(client_addr))

         # Spawn a thread to handle the client
         threading.Thread(target=self.handleMsg, args=(conn, client_addr,)).start()
   
   # This runs in a thread and handles messages from clients
   def handleMsg(self, conn, client_addr):
      # Receive data from client
      clientData = conn.recv(32768).decode("utf-8")

      # Format as message
      clientMsg = Message()
      clientMsg.loadFromString(clientData)

      print("FrontServer got " + clientData)

      # Check if the packet is for setting up a connection
      if clientMsg.getNetInfo() == 0:
         # Add client's public key to our list of clients
         clientPort, clientPublicKey = clientMsg.getPayload().split("|")
         clientPublicKey = TU.deserializePublicKey(clientPublicKey) 
         
         # Build the entry for the client. See clientList above
         clientEntry = ((client_addr[0], clientPort), clientPublicKey)

         if clientEntry not in self.clientList:
            self.clientList.append(clientEntry)
         conn.close()
      elif clientMsg.getNetInfo() == 1: 
         # Process packets coming from a client and headed towards
         # a dead drop. Just forward to next server
         
         # Onion routing stuff
         self.clientLocalKey, newPayload = TU.decryptOnionLayer(
               self.__privateKey, clientMsg.getPayload(), serverType=0)
         clientMsg.setPayload(newPayload)
         
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((self.nextServerIP, self.nextServerPort))
         sock.sendall(str(clientMsg).encode("utf-8"))
         sock.close()
      elif clientMsg.getNetInfo() == 2: 
         # Message going back to client
         # This is where we will have to use the public key to determine
         # which client should get the message...right now we are just
         # sending the message to all clients <- TODO (matthew)
         
         # Onion routing stuff
         newPayload = TU.encryptOnionLayer(self.__privateKey, 
                                           self.clientLocalKey, 
                                           clientMsg.getPayload())
         clientMsg.setPayload(newPayload)
         
         for client in self.clientList:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientPublicKey = client[1]
            clientIP = client[0][0]
            clientPort = int(client[0][1])
            tempSock.connect((clientIP,clientPort))
            tempSock.sendall(str(clientMsg).encode("utf-8"))
            tempSock.close()
      elif clientMsg.getNetInfo() == 3: 
         # Dialing Protocol: Client -> DeadDrop
         print('Dialing Protocol: FrontServer')

         _, newPayload = TU.decryptOnionLayer(
               self.__privateKey, clientMsg.getPayload(), serverType=0)
         clientMsg.setPayload(newPayload)
         
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((self.nextServerIP, self.nextServerPort))
         sock.sendall(str(clientMsg).encode("utf-8"))
         sock.close()
         
   
   # Run server round
   async def runRound(self, round, deadline):
      # Create the new round using our class above
      currentRound = RoundInfo(round, deadline)

      # Let clients send messages during this round only, do not allow
      # another round to start up while one is in progress
      async with self.lock:
         # Add new round to the server's ongoing dictionary of rounds
         self.rounds[round] = currentRound
      
         # Start timer
         startTime = time.process_time()

         # Allow clients to send messages for duration of round
         while time.process_time() - startTime < deadline:
            # TODO: Figure out how to restrict clients to sending messages
            # only within this time frame
            continue
      
         # Now that round has ended, mark current round as closed
         currentRound.open = False
         self.roundID = self.roundID + 1

         # Iterate through clients and have them connect to a new dead drop
         # server
         for client in self.clientList:
            # TODO: Find a way to compute new dead drop server for each
            # client
            continue