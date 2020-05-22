#!/usr/bin/env python3

from message import Message
from Client import Client
from FrontServer import FrontServer
from MiddleServer import MiddleServer
from SpreadingServer import SpreadingServer
from DeadDrop import DeadDrop

def testNetwork():
   # This is the setup we have below with the port number that
   # each host listens on. Note that we specify both the port that
   # the host listens on and the port and IP of the next server in the chain
   #
   # Client    ->  FrontServer -> MiddleServer -> SpreadingServer -> DeadDrop
   # port 7776     port 7777      port 7778       port 7779          port 7780
   
   # We can do any kind of test we want in here...
   
   c = Client('localhost', 7777, 7776)
   front = FrontServer('localhost', 7778, 7777)
   middle = MiddleServer('localhost', 7779, 7778)
   spreading = SpreadingServer([('localhost', 7780)], 7779)
   dead = DeadDrop(7780)
   
   # Set the keys in the client
   ppk_frontServer = front.getPublicKey()
   ppk_middleServer = middle.getPublicKey()
   ppk_spreadingServer = spreading.getPublicKey()
   ppk_deadDropServer = dead.getPublicKey()
   c.chainServersPublicKeys = [ ppk_frontServer, ppk_middleServer, ppk_spreadingServer]
   c.deadDropServersPublicKeys = [ ppk_deadDropServer ] 
   
   # Prepare the message
   m = Message()
   m.setPayload("Hello Torzela!")
   
   # Send this message into Torzela and get a response
   returned = c.sendAndRecvMsg(m)
   
   # Print the message we receive. Right now, the message will go
   # through the network until it reaches the Dead Drop Server, then
   # it will just be sent back, so we should get "Hello Torzela!" here
   print("RECEIVED: " + returned.getPayload())