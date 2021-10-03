#! /usr/bin/python3

import socket
from struct import *
from ctypes import *

class IPv6(Structure):
    _fields_= [
        ("version", c_ubyte, 4),        #4
        ("traffic", c_ubyte),           #8
        ("flow_label", c_ulong, 20),    #20
        ("lenn", c_ushort),             #16
        ("nextt", c_ubyte),             #8
        ("hop", c_ubyte),               #8
        ("src_1", c_ulonglong),         #64
        ("src_2", c_ulonglong),         #64
        ("dst_1", c_ulonglong),         #64
        ("dst_2", c_ulonglong)          #64
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        pass