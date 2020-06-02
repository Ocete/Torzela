#!/usr/bin/env python3

import socket
import threading
import time
from collections import defaultdict
from message import Message
import TorzelaUtils as TU
import sys



class DeadDrop:
    # Set local port to listen on
   def __init__(self, localPort):
      self.localPort = localPort

      # This will hold the lists of server that have connected
      # to this dead drop. It will contain tuples in the form
      # (<IP>, <Port>)
      # where <IP> is the previous server's IP address and <Port>
      # is the port the previous server is using
      self.previousServers = []

      # This will hold the list of dead drop IDs that each message 
      # wants to access. The idea here is that if two IDs match,
      # we'll swap their positions in the clientMessages array
      # so that the messages are properly exchanged.
      self.deadDropIDs = []

      # Used for onion routing in the conversational protocol  
      # The keys and messages will be updated each round
      self.clientLocalKeys = []
      self.clientMessages = []

      # The server keys
      self.__privateKey, self.publicKey = TU.generateKeys(
         TU.createKeyGenerator())

      self.invitations = []

      # Setup main listening socket to accept incoming connections
      threading.Thread(target=self.listen, args=()).start()
      
   def getPublicKey(self):
      return TU.serializePublicKey(self.publicKey)

   # This is where all messages are handled
   def listen(self):
      # Listen for incoming connections
      listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      listenSock.bind(('localhost', self.localPort))
      listenSock.listen(10)

      while True:
         print("Dead Drop awaiting connections")
         conn, client_addr = listenSock.accept()

         print("Dead Drop accepted connection from " + str(client_addr))

         # Spawn a thread to handle the connection
         threading.Thread(target=self.handleMsg,
                           args=(conn, client_addr)).start()

   # This runs in a thread and handles connections from other servers
   def handleMsg(self, conn, client_addr):
      # Receive data from previous server
      clientData = conn.recv(32768).decode("utf-8")

      # Format as message
      clientMsg = Message()
      clientMsg.loadFromString(clientData)

      print("Dead Drop got " + clientData)

      # Check if the packet is for setting up a connection
      if clientMsg.getNetInfo() == 0:
         # Add previous server's IP and port to our list of clients
         serverEntry = (client_addr[0], clientMsg.getPayload())
         if serverEntry not in self.previousServers:
               self.previousServers.append(serverEntry)

      # Check if the packet is for sending a message
      elif clientMsg.getNetInfo() == 1:
         # In here, packets were trying to reach this server

         # First, close the connection. This may seem
         # weird, but at this point we already have the message
         # and are going to send the message back to all of the
         # connected servers anyways
         conn.close()

         # Onion routing stuff
         clientLocalKey, clientChain, deadDrop, newPayload = TU.decryptOnionLayer(
              self.__privateKey, clientMsg.getPayload(), serverType=2)
         clientMsg.setPayload(newPayload)

         # self.clientLocalKey -> the key used to encrypt the RESPONSE
         # clientChain -> the SpreadingServer where the RESPONSE should be sent
         # deadDrop -> the deadDrop this message is accessing
         # newPayload -> RESPONSE message body
         
         # Save the message data
         self.deadDropIDs.append(deadDrop)
         self.clientLocalKeys.append(clientLocalKey)
         self.clientMessages.append(clientMsg)

         if len(self.clientMessages) == self.nMessages:
            self.runRound()
    
      elif clientMsg.getNetInfo() == 4: 
         # In here, we handle the first message sent by the previous server.
         # It notifies us of a new round and how many messages are coming
         
         # TODO -> Add lock to this whole part
         # TODO -> make this per spreading server with a dict
         
         self.nMessages = int(clientMsg.getPayload())
         self.clientMessages = []
         self.clientLocalKeys = []
      
      elif clientMsg.getNetInfo() == 3:
         conn.close()
         # Decrypt Dead Drop Layer
         self.clientLocalKey, clientChain, deadDrop, invitation = TU.decryptOnionLayer(
            self.__privateKey, clientMsg.getPayload(), serverType=2)

         # Add message to list of invitations
         self.invitations.append(invitation)
         return

      elif clientMsg.getNetInfo() == 6:
         if not self.invitations:
            return

         clientPort, clientPublicKey = clientMsg.getPayload().split("|")
         clientPublicKey = TU.deserializePublicKey(clientPublicKey)

         for invitation in self.invitations:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tempSock.connect(('localhost', int(clientPort)))
            data = str(invitation).encode("utf-8")
            tempSock.sendall(data)
            tempSock.close()
         return
         
   # This method matches the messages accessing equal dead drops and
   # sends the responses back to the spreading servers
   def runRound(self):
      
      # The following code computes the matches between different clients
      # It creats a dictionary of dead drop IDs, linking each ID with their
      # index of occurence in self.deadDropIDs

      # If a dead drop ID has two indices, then we swap the values at those
      # indexes in order to exchange messages

      # If a dead drop ID has only one index, then we change that value at
      # that index in the messages list to ""
      
      defaultList = defaultdict(list)

      for index, element in enumerate(self.deadDropIDs):
	      defaultList[element].append(index)

      # Create two separate dictionaries, one for IDs which only appeared
      # once and one for IDs which appeared twice
      uniqueIDs = { k : v for k,v in defaultList.items() if len(v) == 1}
      dupIDs = { k : v for k,v in defaultList.items() if len(v) == 2}

      # Return an empty message to clients who received no response
      for id, indices in uniqueIDs.items():
         m = Message()
         m.setPayload("")
         self.clientMessages[indices[0]] = m

      # Return the swapped messages for clients who are connected to the
      # same dead drop
      for id, indices in dupIDs.items():
	      temp = self.clientMessages[indices[0]]
	      self.clientMessages[indices[0]] = self.clientMessages[indices[1]]
	      self.clientMessages[indices[1]] = temp

      
      # Encrypt all the messages before sending them back
      for msg, clientLocalKey in zip(self.clientMessages, 
                                     self.clientLocalKeys):
         newPayload = TU.encryptOnionLayer(self.__privateKey, 
                                           clientLocalKey, 
                                           msg.getPayload())
         msg.setPayload(newPayload)
         
         # We need to set this to 2 so that the other servers
         # in the chain know to send this back to the client
         msg.setNetInfo(2)
         
      
      # Send message back to all spreading servers
      for prevServer in self.previousServers:
         prevServerIP = prevServer[0]
         prevServerPort = int(prevServer[1])
         for msg in self.clientMessages:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tempSock.connect((prevServerIP, prevServerPort))
            tempSock.sendall(str(msg).encode("utf-8"))
            tempSock.close()
         
      
      # Restart all the data for the next round. Right now this is duplicated
      # But I think it will be necesary to do it here for multiple spreading
      # servers so leaving it here so I remember later
      self.clientMessages = []
      
