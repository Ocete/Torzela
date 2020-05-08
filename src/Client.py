#!/usr/bin/env python3

import socket
import sys
import threading
import time
from message import Message

class Client:
   # Configure the client with the IP and Port of the next server
   def __init__(self, serverIP, serverPort, localPort, publicKey):
      # serverIP and serverPort is the IP and port of the next
      # server in the chain
      self.serverIP = serverIP
      self.serverPort = serverPort

      # When getting a response from the network, this client
      # will listen on this port
      self.localPort = localPort
  
      # The public key of the client. Used by the front server
      # to determine where to send a packet
      self.publicKey = publicKey

      # We need to spawn off a thread here, else we will block the
      # entire program (i.e. if we create the client then the server
      # in our python program, the client will block and wait for
      # the server to come up...but that can't happen until the
      # client is done configuring, so we would end up with deadlock)
      threading.Thread(target=self.setupConnection, args=()).start()

   def setupConnection(self):
      # Connect to the next server to give it our listening port
      # and public key. The server will also be able to tell our ip
      # address just by receiving a connection from us
      # This is the setup message below that will hold this information
      setupMsg = Message()
      setupMsg.setNetInfo(0)
      setupMsg.setPayload("{}|{}".format(self.localPort, self.publicKey))
 
      self.connectionMade = False
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # While we have not been able to connect to the next server
      # in the chain...
      while not self.connectionMade:
         try:
            # Try to connect and send it our setup message
            self.sock.connect((self.serverIP, self.serverPort))
            self.sock.sendall(str.encode(str(setupMsg)))
            self.connectionMade = True
         except:
            # Just keep trying to connect...
            # Add a delay here so we don't consume a 
            # lot of CPU time
            time.sleep(1)
      print("Client successfully connected!")
      # Close the connection after we verify everything is working
      self.sock.close()


   # Send and receive a message from Torzela
   # Because we always receive a response, it doesn't
   # make sense to have two separate send and receive methods
   def sendAndRecvMsg(self, msg):
      # If the initial setup has not gone through,
      # then just block and wait. We can't send anything
      # before we know the network is up and working
      while not self.connectionMade:
         time.sleep(1)

      # Connect to next server
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.connect((self.serverIP, self.serverPort))

      # Send our message to the server
      # the 1 means we are sending the message towards
      # a dead drop 
      msg.setNetInfo(1)
      self.sock.sendall(str.encode(str(msg)))
      self.sock.close()

      # Now open up the listening port to listen for a response
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.bind(('localhost', self.localPort))
      self.sock.listen(1) # listen for 1 connection
      conn, server_addr = self.sock.accept()
      # All messages are fixed to 4K
      recvStr = conn.recv(4096)
      conn.close()

      # Convert response to message and return it
      m = Message()
      m.loadFromString(recvStr)
      
      return m
