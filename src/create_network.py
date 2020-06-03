#!/usr/bin/env python3


from Client import Client
from FrontServer import FrontServer
from MiddleServer import MiddleServer
from SpreadingServer import SpreadingServer
from DeadDrop import DeadDrop
import TorzelaUtils as TU
import time


class Torzela:
   def __init__(self, port):
      self.front = FrontServer('', port+1, port)
      self.middle = MiddleServer('', port+2, port+1)
      self.spreading = SpreadingServer([('', port+3)], port+1)

      self.front.chainServersPublicKeys.extend([self.front.getPublicKey(), 
                                          self.middle.getPublicKey(), 
                                          self.spreading.getPublicKey()])
      
      self.dead = DeadDrop(port+3)

      self.front.deadDropServersPublicKeys.append(self.dead.getPublicKey())
      return


if __name__ == "__main__":
   port = int(input('Select port to create network: '))
   chain = Torzela(port)

