#!/usr/bin/env python3

from message import Message
from Client import Client
from FrontServer import FrontServer
from MiddleServer import MiddleServer
from SpreadingServer import SpreadingServer
from DeadDrop import DeadDrop
import TorzelaUtils as TU
import threading

def testNetwork():
   # This is the setup we have below with the port number that
   # each host listens on. Note that we specify both the port that
   # the host listens on and the port and IP of the next server in the chain
   #
   # Client    ->  FrontServer -> MiddleServer -> SpreadingServer -> DeadDrop
   # port 7776     port 7777      port 7778       port 7779          port 7780
   
   # We can do any kind of test we want in here...
   
   initial_port = 7734
   
   c = Client('localhost', initial_port+1, initial_port)
   front = FrontServer('localhost', initial_port+2, initial_port+1)
   middle = MiddleServer('localhost', initial_port+3, initial_port+2)
   spreading = SpreadingServer([('localhost', initial_port+4)], initial_port+3)
   dead = DeadDrop(initial_port+4)
   
   # Set the keys in the client
   ppk_frontServer = front.getPublicKey()
   ppk_middleServer = middle.getPublicKey()
   ppk_spreadingServer = spreading.getPublicKey()
   ppk_deadDropServer = dead.getPublicKey()
   c.chainServersPublicKeys = [ ppk_frontServer, ppk_middleServer, ppk_spreadingServer]
   c.deadDropServersPublicKeys = [ TU.deserializePublicKey(ppk_deadDropServer) ]
   c.partnerPublicKey = c.publicKey
   # c.privateDeadDropServerKey = TU.deserializePrivateKey(dead.getPrivateKey())
   
   # Prepare the message
   m = Message()
   m.setPayload("Hello Torzela!")   
   
   # Send this message into Torzela and get a response
   returned = c.sendAndRecvMsg(m)
   
   # Print the message we receive. Right now, the message will go
   # through the network until it reaches the Dead Drop Server, then
   # it will just be sent back, so we should get "Hello Torzela!" here
   print("RECEIVED: " + returned.getPayload())


def testDialingProtocol():
   # This is the setup we have below with the port number that
   # each host listens on. Note that we specify both the port that
   # the host listens on and the port and IP of the next server in the chain
   #
   # Client    ->  FrontServer -> MiddleServer -> SpreadingServer -> DeadDrop
   # port 7776     port 7777      port 7778       port 7779          port 7780
   
   # We can do any kind of test we want in here...
   
   initial_port = 7734
   clients = [Client('localhost', initial_port+1, initial_port-1), Client('localhost', initial_port+1, initial_port)]
   front = FrontServer('localhost', initial_port+2, initial_port+1)
   middle = MiddleServer('localhost', initial_port+3, initial_port+2)
   spreading = SpreadingServer([('localhost', initial_port+4)], initial_port+3)
   dead = DeadDrop(initial_port+4)
   
   # Set the keys in the client
   ppk_frontServer = front.getPublicKey()
   ppk_middleServer = middle.getPublicKey()
   ppk_spreadingServer = spreading.getPublicKey()
   ppk_deadDropServer = dead.getPublicKey()

   for client in clients:
      client.chainServersPublicKeys = [ppk_frontServer, ppk_middleServer, ppk_spreadingServer]
      client.deadDropServersPublicKeys = [ TU.deserializePublicKey(ppk_deadDropServer) ]


   # Let client 1 listen to invitations in its designated invitation deaddrop
   invitation = clients[1].download_invitations(initial_port+4)
   
   # Let client 0 dial client 1 (1st arg = partner w/ whom to contact w/)
   thread = threading.Thread(target=clients[0].dial, args=(clients[1].publicKey,))
   thread.start()
   
   print("RECEIVED INVITATION: " + invitation.getPayload())

   


if __name__ == "__main__":
   testDialingProtocol()
