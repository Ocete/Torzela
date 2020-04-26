#!/usr/bin/env python3

#A message object which is used to
#communicate between the clients and servers
class Message:
   def __init__(self, msg_type, payload):
      # A message has two components:
      #   1) A type (which is an integer) this is us
      #      to distinguish between different types of messages.
      #      I have not made a standard for this; just agree upon
      #      what type of message is what value and use it consistently
      #
      #   2) A payload which is a string. This is the actual message
      #      that is being sent
      self.msg_type = msg_type
      self.payload = payload

   # Store the content of the message in a string for transmission
   # over the network
   def __str__(self):
      return str(self.msg_type) + "|" + message

   # Reverse the __str__ method: Given a string, construct the message 
   def load(self, string):
      self.msg_type, self.payload = string.split('|', 1)

