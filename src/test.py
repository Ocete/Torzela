#!/usr/bin/env python3

from Client import Client
from FrontServer import FrontServer
from MiddleServer import MiddleServer
from SpreadingServer import SpreadingServer
from DeadDrop import DeadDrop
import TorzelaUtils as TU
import threading
import time

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

   # Prepare the message
   c.newMessage("Hello Torzela!")   
   
   # When the next round starts, the Front Server will notify the client,
   # who will send the message "Hello Torzela". Right now, the message will go
   # through the network until it reaches the Dead Drop Server, then
   # it will just be sent back, so we should get "Hello Torzela!" here
   time.sleep(50000)


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
      
      # potential partners = set of all other available clients to speak to
      # not the same as partner client, the client w/ whom you are currently speaking with
      client.potential_partner_pks = [client.publicKey for client in clients]
   
   dead.client_private_public = (clients[0].publicKey, clients[1].get_private())
   print(dead.client_private_public)
   # Let client 0 dial client 1 (1st arg = partner w/ whom to contact w/)
   clients[0].dial(clients[1].publicKey)
   # Let client 1 listen to invitations in its designated invitation deaddrop
   #invitation = clients[1].download_invitations(initial_port+4)
   
   # print("RECEIVED INVITATION: " + invitation.getPayload())


if __name__ == "__main__":
   testDialingProtocol()
