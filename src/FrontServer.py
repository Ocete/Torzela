#!/usr/bin/env python3

import socket
import sys
import threading
import time
from message import Message

class FrontServer:
   # Set the IP and Port of the next server. Also set the listening port
   # for incoming connections. The next server in the chain can
   # be a Middle Server or even a Dead Drop Server
   def __init__(self, nextServerIP, nextServerPort, localPort):
      self.nextServerIP = nextServerIP
      self.nextServerPort = nextServerPort
      self.localPort = localPort

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
      clientData = conn.recv(4096).decode("utf-8")

      # Format as message
      clientMsg = Message()
      clientMsg.loadFromString(clientData)

      print("FrontServer received " + clientData)

      # Check if the packet is for setting up a connection
      if clientMsg.getNetInfo() == 0:
         # Add client's public key to our list of clients
         clientPort, clientPublicKey = clientMsg.getPayload().split("|")

         # Build the entry for the client. See clientList above
         clientEntry = ((client_addr[0], clientPort), clientPublicKey)

         if clientEntry not in self.clientList:
            self.clientList.append(clientEntry)
         conn.close()
      elif clientMsg.getNetInfo() == 1: 
         # Process packets coming from a client and headed towards
         # a dead drop. Just forward to next server
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sock.connect((self.nextServerIP, self.nextServerPort))
         sock.sendall(str.encode(str(clientMsg)))
         sock.close()
      elif clientMsg.getNetInfo() == 2: # Message going back to client
         # This is where we will have to use the public key to determine
         # which client should get the message...right now we are just
         # sending the message to all clients
         for client in self.clientList:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientPublicKey = client[1]
            clientIP = client[0][0]
            clientPort = int(client[0][1])
            tempSock.connect((clientIP,clientPort))
            tempSock.sendall(str.encode(str(clientMsg)))
            tempSock.close()
