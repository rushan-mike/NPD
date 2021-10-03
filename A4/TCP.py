#! /usr/bin/python3

import socket
from struct import *
from ctypes import *

class TCP(Structure):
    _fields_= [
        ("src_port", c_ushort),     #16
        ("dst_port", c_ushort),     #16
        ("seq_num", c_ulong),       #32
        ("ack_num", c_ulong),       #32
        ("offset", c_ubyte, 4),     #4
        ("res", c_ubyte, 4),        #4
        ("flag", c_ushort, 8),      #8
        # ("win_size", c_ushort),   #16
        # ("summ", c_ushort),       #16
        # ("urg_point", c_ushort)   #16
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        
        self.flag_map = {1:"FIN", 2:"SYN", 4:"RST", 8:"PSH", 16:"ACK", 32:"URG", 64:"ECE", 128:"CWR"}

        self.src_port_flip = int.from_bytes(pack('@H',self.src_port),"big")
        self.dst_port_flip = int.from_bytes(pack('@H',self.dst_port),"big")
        self.seq_num_flip = int.from_bytes(pack('@L',self.seq_num),"big")
        self.ack_num_flip = int.from_bytes(pack('@L',self.ack_num),"big")

        try:
            self.flagg = self.flag_map[self.flag]
        except:
            self.flagg = str(self.flag)