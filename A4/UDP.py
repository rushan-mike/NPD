#! /usr/bin/python3

import socket
from struct import *
from ctypes import *

class UDP(Structure):
    _fields_= [
        ("src_port", c_ushort),     #16
        ("dst_port", c_ushort),     #16
        ("lenn", c_ushort),         #16
        ("summ", c_ushort)          #16
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):

        self.src_port_flip = int.from_bytes(pack('@H',self.src_port),"big")
        self.dst_port_flip = int.from_bytes(pack('@H',self.dst_port),"big")
        self.lenn_flip = int.from_bytes(pack('@H',self.lenn),"big")
        self.summ_flip = int.from_bytes(pack('@H',self.summ),"big")