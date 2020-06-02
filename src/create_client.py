#!/usr/bin/env python3

from Client import Client
from FrontServer import FrontServer
from MiddleServer import MiddleServer
from SpreadingServer import SpreadingServer
from DeadDrop import DeadDrop
import TorzelaUtils as TU
import time




def new_client(clientId, new_port, front_server_port):
   print(f"Creating client {clientId} on port {new_port}")
   client = Client('localhost', front_server_port, new_port, clientId=clientId)
   return client

if __name__ == "__main__":
   new_client(1, 7754, 7750)