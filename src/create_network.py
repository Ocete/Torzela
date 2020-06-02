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
      self.front = FrontServer('localhost', port+1, port)
      self.middle = MiddleServer('localhost', port+2, port+1)
      self.spreading = SpreadingServer([('localhost', port+3)], port+1)

      self.front.chainServersPublicKeys = [self.front.getPublicKey(), 
                                          self.middle.getPublicKey(), 
                                          self.spreading.getPublicKey()]
      
      self.dead = DeadDrop(port+3)

      self.front.chainServersPublicKeys.append(self.dead.getPublicKey())
      return


if __name__ == "__main__":
   chain = Torzela(7750)
