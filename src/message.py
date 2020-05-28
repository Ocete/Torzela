#!/usr/bin/env python3

# A message object which is used to
# communicate between the clients and servers
# The netinfo field is only used in the networking
# subsystem 
class Message:
   # A message has three components:
   #   1) A type (which is an integer) this is us
   #      to distinguish between different types of messages.
   #      (i.e. server round message, encryption message, etc.)
   #
   #   2) A payload which is a string. This is the actual message
   #      that is being sent
   #  
   #   3) The netinfo field, which is used internally by the
   #      networking subsystem
   def __init__(self):
      # Just initialize these to some default value
      self.netinfo = "0"
      self.msg_type = "0"
      self.payload = ""

   # Netinfo field values:
   #  Value 0: Messages with this value are used for 
   #           configuring the initial channel
   #  Value 1: Used when the packet is going from the client
   #           and is headed towards the dead drop
   #  Value 2: Used when the packet is going from the 
   #           dead drop back to the client. The dead drop
   #           will flip this value from 1 to 2 when sending
   #           the message back
   #  Value 4: Used during the conversational protocol between servers
   #           to show how many messages will be sent to the next server
   #           in this round
   def setNetInfo(self, netinfo):
      self.netinfo = str(netinfo)

   def getNetInfo(self):
      return int(self.netinfo)

   def setType(self, msg_type):
      self.msg_type = str(msg_type)
  
   def getType(self):
      return int(self.msg_type)

   def setPayload(self, payload):
      self.payload = payload
 
   def getPayload(self):
      return self.payload

   # Store the content of the message in a string for transmission
   # over the network
   def __str__(self):
      return self.netinfo + "|" + self.msg_type + "|" + self.payload

   # Reverse the __str__ method: Given a string, construct the message 
   def loadFromString(self, string):
      # The "2" means we only split on the first two occurrences of "|"
      # This is to make sure we don't try to split on the data section
      self.netinfo, self.msg_type, self.payload = str(string).split('|', 2)

