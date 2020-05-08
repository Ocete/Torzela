#!/usr/bin/env python3

import socket
import sys
import threading
import time
from message import Message

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
         threading.Thread(target=self.handleMsg, args=(conn, client_addr,)).start()
   
   # This runs in a thread and handles connections from other servers
   def handleMsg(self, conn, client_addr):
      # Receive data from previous server
      clientData = conn.recv(4096).decode("utf-8")

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
      elif clientMsg.getNetInfo() == 1: 
         # Forward packet back. Whoever handles the dead drops
         # will be working here mainly. Right now this just
         # sends the packet back to all connected clients
      
         # First, close the connection. This may seem
         # weird, but at this point we already have the message
         # and are going to send the message back to all of the 
         # connected servers anyways
         conn.close()

         # We need to set this to 2 so that the other servers
         # in the chain know to send this back to the client
         clientMsg.setNetInfo(2)
         
         # Send message back to all previous servers
         for prevServer in self.previousServers:
            tempSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            prevServerIP = prevServer[0]
            prevServerPort = int(prevServer[1])
            tempSock.connect((prevServerIP, prevServerPort))
            tempSock.sendall(str.encode(str(clientMsg)))
            tempSock.close()
