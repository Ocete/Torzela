#!/usr/bin/env python3

from Client import Client
from FrontServer import FrontServer
from MiddleServer import MiddleServer
from SpreadingServer import SpreadingServer
from DeadDrop import DeadDrop
import TorzelaUtils as TU
import time



if __name__ == "__main__":
    # torzella_port = int(input('Enter Torzella Network Port: '))

    port = int(input('Enter port to host local messaging client: '))
    # name = str(input('Enter Your Name: '))
    
    torzella_port = 7050
    name = 'Gangll'

    client = Client('', torzella_port, port, client_name=name)
    
    print(f'Welcome to Torzela {name}!')

    partner = str(input('Who would you like to contact? '))
    
    client.dial(partner)

    while True:
        message = input(f'Message to {partner}: ')
        client.newMessage(message)
