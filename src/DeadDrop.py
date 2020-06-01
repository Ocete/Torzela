#!/usr/bin/env python3

import socket
import threading
import time
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

      # Used for onion rotuing in the conversational protocol  
      # The keys and messages will be updated each round
      self.clientLocalKeys = []
      self.clientMessages = []

      # The server keys
      self.__privateKey, self.publicKey = TU.generateKeys(
         TU.createKeyGenerator())

      self.invitations = []

      self.client_private_public = None

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
         # Forward packet back. Whoever handles the dead drops
         # will be working here mainly. Right now this just
         # sends the packet back to all connected clients

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
         print('Dialing Protocol REACHED DEADDROP')
         conn.close()
         # Decrypt Dead Drop Layer
         self.clientLocalKey, clientChain, deadDrop, newPayload = TU.decryptOnionLayer(
            self.__privateKey, clientMsg.getPayload(), serverType=2)
         clientMsg.setPayload(newPayload)


         
         sharedSecret = TU.computeSharedSecret(self.client_private_public[1], self.client_private_public[0])
         newPayload = TU.decryptMessage(sharedSecret, clientMsg.getPayload())
         print('hello')
         print('new_payload', newPayload)
         quit()

         # Add message to list of invitations
         self.invitations.append(clientMsg)
         return

      elif clientMsg.getNetInfo() == 6:
         print('Download Invitations')
         if not self.invitations:
            return

         clientPort, clientPublicKey = clientMsg.getPayload().split("|")
         clientPublicKey = TU.deserializePublicKey(clientPublicKey)

         for invitation in self.invitations:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tempSock.connect(('localhost', int(clientPort)))
            tempSock.sendall(str(invitation).encode("utf-8"))
            tempSock.close()

         return
         
   # This method matches the messages accessing equal dead drops and
   # sends the responses back to the spreading servers
   def runRound(self):
      
      # TODO (edric): compute the matches between the different clients.
      # That is, for every two clients, if they are accessing the same dead
      # drop, swap the messages, don't change anything else. 
      # If a client does not recieve a response, return the empty message: ""
      time.sleep(1)
      
      
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
      
