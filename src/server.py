#!/usr/bin/env python3

import socket
import sys
import threading
from message import Message

# Usage:
# python3 server.py <next server>
#
# Where <next server> is the IP address of the
# next server.  If <next server> is "deaddrop", this
# server will be a deaddrop

class Server:
   # Initialize the server. This will spawn a thread to handle
   # incoming and outgoing messages.  
   def __init__(self, nextServer):
      # If self.nextServer == "deaddrop", this is a deaddrop server
      self.nextServer = nextServer
      # Servers will always operate on port 2121
      self.serverPort = 2122
      
   # This is the main event loop for the server. It will listen for incoming
   # connections, process the requests, and then listen for more connections
   def listen(self):
      # Sets up the server's network connection.
      # This is a two-step process:
      # 
      # 1) Bind the server to listen on localhost to
      #    accept connections
      # 2) Connect to the next server in the mixnet
      if self.nextServer != "deaddrop":
         # 1. Bind to localhost. We need to have the sock object
         #    available to other methods.
         self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         print("Starting server on port " + str(self.serverPort))
         self.listenSock.bind( ('localhost', self.serverPort) )

         # 2. Connect to the next server in the mixnet
         self.forwardSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         print("Connecting to next server at " + str(self.nextServer))
         self.forwardSock.connect( (self.nextServer, self.serverPort) )

      # Else this server has been setup as a dead drop. In this case, we will
      # be accepting and returning messages to the same server
      else:
         self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         print("Starting deaddrop on port " + str(self.serverPort))
         self.listenSock.bind( ('localhost', self.serverPort) )
         
         # We will send responses back to the same host
         self.forwardSocket = self.listenSock

 
      self.listenSock.listen(10)
   
      while True:
         print("Server awaiting connection")
         conn, client_addr = self.listenSock.accept()

         print("Accepted connection from " + str(client_addr))

         # Spawn a thread to handle the message
         threading.Thread(target=self.handleMsg, args=(conn, client_addr,)).start()
   
   # This runs in a thread and handles messages
   def handleMsg(self, conn, client_addr):
      #Process the message...
      # ...
      # ...
      # Then send it back to the client
      recvStr = conn.recv(1024)
      print("Received: " + str(recvStr))

      # Send message back to client
      msg = Message()
      msg.setType(0)
      msg.setPayload("Hello, client!")

      conn.sendall(str.encode(str(msg)))
      conn.close()
         

s = Server("deaddrop")
s.listen()
