#! /usr/bin/python3

import socket
from struct import *
from ctypes import *

class ICMP(Structure):
    _fields_= [
        ("ttype", c_ubyte),     #8
        ("code", c_ubyte),      #8
        ("check", c_ushort),    #16
        ("idd", c_ushort),      #16
        ("seq", c_ushort),      #16
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        
        self.check_flip = int.from_bytes(pack('@H',self.check),"big")
        self.idd_flip = int.from_bytes(pack('@H',self.idd),"big")
        self.seq_flip = int.from_bytes(pack('@H',self.seq),"big")
