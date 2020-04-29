#!/usr/bin/env python3

import socket
import sys
from message import Message

class Client:
   # Initialize the client with the IP of the Vuvuzela server
   def __init__(self, serverIP):
      self.serverIP = serverIP

      # Servers will always operate on port 2121
      self.serverPort = 2122

   # Send a message into the Vuvuzela network and wait for a response
   def sendMsg(self, msg):

      # Create socket to communicate through
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

      # Display the server IP and the port we are connecting to
      print("Connecting to " + str(self.serverIP) + " on port " + str(self.serverPort))

      # Connect to server
      self.sock.connect( (self.serverIP, self.serverPort) )

      # Now we use self.sock to send/receive messages 

      # Send the message to the Vuvuzela server 
      self.sock.sendall(str.encode(str(msg)))

      # Hold the response in recvStr
      recvStr = ""
      # Read response in 1024 byte blocks
      data = self.sock.recv(1024)
      # Continue to read while there is data
      while data:
         # Append new data
         recvStr += str(data)
         # Read next block of data
         data = self.sock.recv(1024)

      # Convert the string response into a Message object
      recvMsg = Message()
      recvMsg.loadFromString(recvStr)

      print("Got message " + str(recvMsg))

      # Now process the received message...this is where my
      # job ends and your's begins!
    

# For testing purposes, we will have the server running locally,
# so we specify 'localhost'
c = Client('localhost')

# The message type here (the 0) is kind of arbitrary; just agree
# on a standard (i.e. type 0 is for messages, type 1 is for 
# encryption keys, etc)
msg = Message()
msg.setType(0)
msg.setPayload("Testing...")

# Send the message
c.sendMsg(msg)
