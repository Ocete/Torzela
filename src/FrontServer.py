#!/usr/bin/env python3

import socket
import threading
import asyncio
import time
import pickle
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
      self.roundDuration = 2
      self.currentRound = ""

      self.chainServersPublicKeys = []
      self.deadDropServersPublicKeys = []

      # This will allow us to associate a client with it's public key
      # So that we can figure out which client should get which packet
      # Entries are in the form
      # ((<IP>,<Port>), <Public Key>)     (i.e. (('localhost', 80), "mykey") )
      # where <IP> is the client's IP address, <Port> is the client's
      # listening port, and <Public Key> is the client's public key
      self.clientList = []

      # These arrays hold their information during each round. Position i-th
      # of each array represents their respective data:
      #    key ; (ip, port) ; message -- respectively
      # for the message that arrived the i-th in the current round.
      self.clientLocalKeys = []
      self.clientMessages = []
      self.clientPublicKeys = []
      
      # The server keys
      self.__privateKey, self.publicKey = TU.generateKeys( 
            TU.createKeyGenerator() )         

      # We need to spawn off a thread here, else we will block
      # the entire program
      threading.Thread(target=self.setupConnection, args=()).start()
 
      # Setup main listening socket to accept incoming connections
      threading.Thread(target=self.listen, args=()).start()

      # Create a new thread to handle the round timings
      threading.Thread(target=self.manageRounds, args=()).start() 

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
      clientIP = client_addr[0]

      print("FrontServer got " + clientData)

      # Check if the packet is for setting up a connection
      if clientMsg.getNetInfo() == 0:
         # Add client's public key to our list of clients
         clientPort, clientPublicKey = clientMsg.getPayload().split("|")
         
         # Build the entry for the client. See clientList above
         # Store the public key as a string
         clientEntry = ((clientIP, clientPort), clientPublicKey)

         if clientEntry not in self.clientList:
            self.clientList.append(clientEntry)
         
         serialized_pks = [TU.serializePublicKey(pk) for pk in self.chainServersPublicKeys]
         
         data = pickle.dumps(serialized_pks)

         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect(('localhost', int(clientPort)))
         sock.sendall(str(data).encode("utf-8"))
         sock.close()
         
         conn.close()
      elif clientMsg.getNetInfo() == 1: 
         # Process packets coming from a client and headed towards
         # a dead drop only if the current round is active and the client 
         # hasn't already send a msessage
         clientPublicKey, payload = clientMsg.getPayload().split("#", 1)
         if self.currentRound.open and clientPublicKey not in self.clientPublicKeys:
            
            # Decrypt one layer of the onion message
            clientLocalKey, newPayload = TU.decryptOnionLayer(
                  self.__privateKey, payload, serverType=0)
            clientMsg.setPayload(newPayload)
            
            # Save the message data
            # TODO (jose) -> use the lock here. Multiple threads could try to 
            # access this info at the same time. In fact, we should process 
            # messages with netinfo == 1 ONE AT A TIME or could create inconsistences.
            self.clientPublicKeys.append(clientPublicKey)
            self.clientLocalKeys.append(clientLocalKey)
            self.clientMessages.append(clientMsg)
         
      elif clientMsg.getNetInfo() == 2:
         # TODO -> add a lock here, same as with netinfo == 1
         
         # Encrypt one layer of the onion message
         clientLocalKey = self.clientLocalKeys[ len(self.clientMessages) ] 
         newPayload = TU.encryptOnionLayer(self.__privateKey, 
                                           clientLocalKey, 
                                           clientMsg.getPayload())
         clientMsg.setPayload(newPayload)
         self.clientMessages.append(clientMsg)

      elif clientMsg.getNetInfo() == 3: 
         # Dialing Protocol: Client -> DeadDrop

         _, newPayload = TU.decryptOnionLayer(
               self.__privateKey, clientMsg.getPayload(), serverType=0)
         clientMsg.setPayload(newPayload)
         
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((self.nextServerIP, self.nextServerPort))
         sock.sendall(str(clientMsg).encode("utf-8"))
         sock.close()
   
   # A thread running this method will be in charge of the different rounds
   def manageRounds(self):
      while True:
         time.sleep(10)
         
         # Reset the saved info about the messages for the round before it starts
         self.clientLocalKeys = []
         self.clientIPsAndPorts = []
         self.clientMessages = []
         
         # Create the new round using our class above
         self.currentRound = RoundInfo(round, self.roundDuration)
         self.rounds[self.roundID] = self.currentRound
         print("Front Server starts round: ", self.roundID)
      
         # Tell all the clients that a new round just started
         firstMsg = Message()
         firstMsg.setNetInfo(5)
         for clientIpAndPort, clientPK in self.clientList:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tempSock.connect((clientIpAndPort[0], int(clientIpAndPort[1])))
            tempSock.sendall(str.encode(str(firstMsg)))
            tempSock.close()
            
         # Start timer
         startTime = time.process_time()
   
         # Allow clients to send messages for duration of round
         # Clients can only send message while self.currentRound.open == True
         while time.process_time() - startTime < self.roundDuration:
            continue
         
         # Now that round has ended, mark current round as closed
         self.currentRound.open = False
         
         # TODO -> Once the noice addition is added, the rounds should ALWAYS 
         # run, no matter if there are no messages
         if len(self.clientMessages) > 0:
            # Now that all the messages are stored in self.clientMessages,
            # run the round
            self.runRound()
         
         print("Front Server finished round: ", self.roundID)
         self.roundID += 1
   
   # Runs server round. Assuming that the messages are stores in 
   # self.clientMessages, adds noise, shuffles them and forwards them to
   # the next server
   def runRound(self):
      
      # TODO (jose): Noise addition goes here
      
      # Apply the mixnet by shuffling the messages
      nMessages = len(self.clientMessages)
      permutation = TU.generatePermutation(nMessages)
      shuffledMessages = TU.shuffleWithPermutation(self.clientMessages,
                                                   permutation)
      
      # Also shuffle the messages so they still match the clientMessages:
      # self.clientLocalKeys[ i ] is the key that unlocks message self.clientMessges[ i ]
      # This is used afterwards in handleMessage, getNetInfo() == 2
      self.clientLocalKeys = TU.shuffleWithPermutation(self.clientLocalKeys,
                                                         permutation)
      
      # Forward all the messages to the next server
      # Send a message to the next server notifying of the numbers of 
      # messages that will be sent
      firstMsg = Message()
      firstMsg.setNetInfo(4)
      firstMsg.setPayload("{}".format(nMessages))
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
      
      # Wait until we have received all the responses. These responses are
      # handled in the main thread using the method handleMsg with 
      # msg.getNetInfo == 2
      print("Front Server waiting for responses from Middle Server")
      while len(self.clientMessages) < nMessages:
         continue
      
      # Unshuffle the messages
      self.clientMessages = TU.unshuffleWithPermutation(self.clientMessages, 
                                                        permutation)
      
      # Send each response back to the correct client
      for clientPK, msg in zip(self.clientPublicKeys, self.clientMessages):
         # Find the client ip and port using the clients keys
         matches = [ (ip, port) for ((ip, port), pk) in self.clientList 
                     if clientPK == pk]
         if len(matches) == 0:
            print("Front server error: couldn't find client where to send the response")
            
            print("Lost key: {}".format([clientPK]))
            print(self.clientList)
            
            continue
         elif len(matches) > 1:
            print("Front server error: too many clients where to send the response")
            continue
         clientIP, clientPort = matches[0]
         clientPort = int(clientPort)
         
         print("Trying to send message to {}##{}".format(clientIP, clientPort))
         tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         tempSock.connect((clientIP, clientPort))
         tempSock.sendall(str(msg).encode("utf-8"))
         tempSock.close()
