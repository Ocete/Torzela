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
    client = Client('', front_server_port, new_port)
    return client


if __name__ == "__main__":
    port = int(input('Enter port to host local messaging client: '))
    name = str(input('Enter Your Name:'))
    
    client = Client('', 7750, port, client_name=name)
    partner = str(input('Who would you like to contact?'))
    
    client.dial(partner)

    while True:
        message = input(f'Message to {partner}: ')
        client.newMessage(message)
