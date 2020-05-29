#!/usr/bin/env python3

import socket
import threading
import time
from message import Message
import TorzelaUtils as TU


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

      # Setup main listening socket to accept incoming connections
      threading.Thread(target=self.listen, args=()).start()

      # Used during for onion rotuing in the conversational protocol
      # TODO: make this a dict{ clientIp: key }
      # The key will be updated each time a message from that client is received.
      self.clientLocalKey = ""

      # The server keys
      self.__privateKey, self.publicKey = TU.generateKeys(
         TU.createKeyGenerator())

      self.invitations = []

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
         self.clientLocalKey, clientChain, deadDrop, newPayload = TU.decryptOnionLayer(
               self.__privateKey, clientMsg.getPayload(), serverType=2)
         clientMsg.setPayload(newPayload)

         # self.clientLocalKey -> the key used to encrypt the RESPONSE
         # clientChain -> the SpreadingServer where the RESPONSE should be sent
         # deadDrop -> the deadDrop this message is accessing

         # Here there should be a bunch of code matching messages (maybe not het but yeah=)

         # Here we would normally encrypt the RESPONSE. For testing just send
         # the same message back
         newPayload = TU.encryptOnionLayer(self.__privateKey,
                                             self.clientLocalKey,
                                             clientMsg.getPayload())
         clientMsg.setPayload(newPayload)

         # We need to set this to 2 so that the other servers
         # in the chain know to send this back to the client
         clientMsg.setNetInfo(2)

         # Send message back to all previous servers
         for prevServer in self.previousServers:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            prevServerIP = prevServer[0]
            prevServerPort = int(prevServer[1])
            tempSock.connect((prevServerIP, prevServerPort))
            tempSock.sendall(str(clientMsg).encode("utf-8"))
            tempSock.close()
      elif clientMsg.getNetInfo() == 2:
         conn.close()

         # Onion routing stuff
         self.clientLocalKey, clientChain, deadDrop, newPayload = TU.decryptOnionLayer(
               self.__privateKey, clientMsg.getPayload(), serverType=2)
         clientMsg.setPayload(newPayload)

         # self.clientLocalKey -> the key used to encrypt the RESPONSE
         # clientChain -> the SpreadingServer where the RESPONSE should be sent
         # deadDrop -> the deadDrop this message is accessing

         # Here there should be a bunch of code matching messages (maybe not het but yeah=)

         # Here we would normally encrypt the RESPONSE. For testing just send
         # the same message back
         newPayload = TU.encryptOnionLayer(self.__privateKey,
                                             self.clientLocalKey,
                                             clientMsg.getPayload())
         clientMsg.setPayload(newPayload)

         # We need to set this to 2 so that the other servers
         # in the chain know to send this back to the client
         clientMsg.setNetInfo(2)

         # Send message back to all previous servers
         for prevServer in self.previousServers:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            prevServerIP = prevServer[0]
            prevServerPort = int(prevServer[1])
            tempSock.connect((prevServerIP, prevServerPort))
            tempSock.sendall(str(clientMsg).encode("utf-8"))
            tempSock.close()
      elif clientMsg.getNetInfo() == 3:
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
         print('Dialing Protocol REACHED DEADDROP')
         conn.close()
         # Onion routing stuff
         self.clientLocalKey, clientChain, deadDrop, newPayload = TU.decryptOnionLayer(
            self.__privateKey, clientMsg.getPayload(), serverType=2)
         clientMsg.setPayload(newPayload)
         self.invitations.append(clientMsg)
         return

      elif clientMsg.getNetInfo() == 4:
         print('Ping Download')
         if not self.invitations:
            return

         clientPort, clientPublicKey = clientMsg.getPayload().split("|")
         clientPublicKey = TU.deserializePublicKey(clientPublicKey)
         print(clientPort)
         for invitation in self.invitations:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tempSock.connect(('localhost', int(clientPort)))
            tempSock.sendall(str(invitation).encode("utf-8"))
            tempSock.close()

         return
