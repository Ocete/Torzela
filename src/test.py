#!/usr/bin/env python3

from Client import Client
from FrontServer import FrontServer
from MiddleServer import MiddleServer
from SpreadingServer import SpreadingServer
from DeadDrop import DeadDrop
import TorzelaUtils as TU
import time

def testNetwork():
   # This is the setup we have below with the port number that
   # each host listens on. Note that we specify both the port that
   # the host listens on and the port and IP of the next server in the chain
   #
   # Client    ->  FrontServer -> MiddleServer -> SpreadingServer -> DeadDrop
   # port 7776     port 7777      port 7778       port 7779          port 7780
   # Client 2
   # port 7775
   # We can do any kind of test we want in here...
   
   initial_port = 7630
   
   c = Client('localhost', initial_port+1, initial_port)
   c_partner = Client('localhost', initial_port+1, initial_port-1)
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
   c.deadDropServersPublicKeys = [ ppk_deadDropServer ]
   c.partnerPublicKey = c_partner.publicKey
   
   # Configure your partner
   c_partner.partnerPublicKey = c.publicKey
   c_partner.chainServersPublicKeys = [ ppk_frontServer, ppk_middleServer, ppk_spreadingServer]
   c_partner.deadDropServersPublicKeys = [ TU.deserializePublicKey(ppk_deadDropServer) ]

   # Prepare the message
   c.newMessage("Hello Torzela!")   
   c_partner.newMessage("Hello friend!")
   c.newMessage("Second round!")   
   c.newMessage("Round three baby!")
   
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
   
   initial_port = 7750
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
      client.deadDropServersPublicKeys = [ ppk_deadDropServer ]
      
      # potential partners = set of all other available clients to speak to
      # not the same as partner client, the client w/ whom you are currently speaking with
      client.potential_partner_pks = [client.publicKey for client in clients]
  
   # Let client 0 dial client 1 (1st arg = partner w/ whom to contact w/)
   clients[0].dial(clients[1].publicKey)
   # Let client 1 listen to invitations in its designated invitation deaddrop
   invitation = clients[1].download_invitations(initial_port+4)
   
   print("RECEIVED INVITATION: " + invitation.getPayload())


class Torzela:
   def __init__(self, port):
      self.front = FrontServer('localhost', port+1, port)
      self.middle = MiddleServer('localhost', port+2, port+1)
      self.spreading = SpreadingServer([('localhost', port+3)], port+1)

      self.front.chainServersPublicKeys = [self.front.getPublicKey(), 
                                          self.middle.getPublicKey(), 
                                          self.spreading.getPublicKey()]
      
      self.dead = DeadDrop(port+3)

      self.front.chainServersPublicKeys.append(self.dead.getPublicKey())
      return


 
def new_client(self, clientId, new_port, front_server_port):
   print(f"Creating client {clientId} on port {self.curr_open_port}")
   client = Client('localhost', front_server_port, new_port, clientId=clientId)
   return client


if __name__ == "__main__":
   chain = Torzela(7750)


   # testDialingProtocol()



nextClientId = 1 


   
   
"""
During the test open two terminals. One will have the servers running and the
other one will have the two clients. Open python in both and do, in this order:
   
Terminal 1:
from test import Torzela
torzela = Torzela() # This inits all the servers

Terminal 2:
import test as T # This creates local values that makes everything a little easier
c1 = T.newClient()
c2 = T.newClient()

# Up to this point rounds should be happening already in the server, but with empty messages

# Dialing protocol
c1.dial( c2.getPublicKey() )
c2.download_invitations() # This should automatically connect c2 to c1

# Conversation protocol
c1.newMessage("Hello Torzela!")

# After this you can check the onion routing in the first terminal
"""
   
   
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
