#! /usr/bin/python3

import socket
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, c_ulonglong, c_uint32
from struct import pack


class ESP(Structure):
    _fields_= [
        ("spi", c_ulong),           #32
        ("snum", c_ulong),          #32
        ("payload", c_ubyte*256),   #256*8
        ("pdlen", c_ubyte),         #8
        ("nextt", c_ubyte),         #8
        ("icv", c_ulong)            #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        pass