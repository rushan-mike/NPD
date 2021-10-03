#! /usr/bin/python3

import socket
from struct import *
from ctypes import *

class Ether(Structure):
    _fields_= [
        # ("pre", c_ulonglong, 56),     #56
        # ("deli", c_ubyte),            #8
        # ("mac_dst", c_ulonglong, 48), #48
        ("mac_dst_1", c_ushort),        #16
        ("mac_dst_2", c_ushort),        #16
        ("mac_dst_3", c_ushort),        #16
        # ("mac_src", c_ulonglong, 48), #48
        ("mac_src_1", c_ushort),        #16
        ("mac_src_2", c_ushort),        #16
        ("mac_src_3", c_ushort),        #16
        # ("tag", c_ulong),             #32
        ("etype", c_ushort),            #16
        # ("pload", c_ulonglong),       #512 (46-1500 octets)
        # ("check", c_ulong),           #32
        # ("gap_1", c_ulonglong),       #64
        # ("gap_2", c_ulong),           #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):

        self.etype_map = {"0806":" ARP", "0800":"IPv4", "86DD":"IPv6"}

        self.mac_dst = (self.mac_dst_3 << 32) + (self.mac_dst_2 << 16) + (self.mac_dst_1)
        self.mac_src = (self.mac_src_3 << 32) + (self.mac_src_2 << 16) + (self.mac_src_1)

        self.dst_mac_hex = hex(self.mac_dst)[2:].zfill(12).upper()
        self.src_mac_hex = hex(self.mac_src)[2:].zfill(12).upper()

        self.dst_mac_flip = "".join(reversed([self.dst_mac_hex[i:i+2] for i in range(0, len(self.dst_mac_hex), 2)]))
        self.src_mac_flip = "".join(reversed([self.src_mac_hex[i:i+2] for i in range(0, len(self.src_mac_hex), 2)]))

        self.dst_mac = ":".join(self.dst_mac_flip[i:i+2] for i in range(0, len(self.dst_mac_flip), 2))
        self.src_mac = ":".join(self.src_mac_flip[i:i+2] for i in range(0, len(self.src_mac_flip), 2))

        self.etype_hex = hex(self.etype)[2:].zfill(4).upper()
        self.etype_flip = "".join(reversed([self.etype_hex[i:i+2] for i in range(0, len(self.src_mac_hex), 2)]))

        try:
            self.ethertype = self.etype_map[self.etype_flip]
        except:
            self.ethertype = str(self.etype_flip)