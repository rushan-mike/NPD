#! /usr/bin/python3

import socket
from struct import *
from ctypes import *

class ARP(Structure):
    _fields_= [
        ("hrd_typ", c_ushort),          #16
        ("pro_typ", c_ushort),          #16
        ("hrd_len", c_ubyte),           #8
        ("pro_len", c_ubyte),           #8
        ("opr", c_ushort),              #16
        # ("sen_hrd", c_ulonglong, 48), #48
        ("sen_hrd_1", c_ushort),        #16
        ("sen_hrd_2", c_ushort),        #16
        ("sen_hrd_3", c_ushort),        #16
        ("sen_pro", c_uint32),          #32
        # ("tar_hrd", c_ulonglong, 48), #48
        ("tar_hrd_1", c_ushort),        #16
        ("tar_hrd_2", c_ushort),        #16
        ("tar_hrd_3", c_ushort),        #16
        ("tar_pro", c_uint32)           #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        self.opr_map = {1:"request", 2:"reply"}

        self.sen_hrd = (self.sen_hrd_3 << 32) + (self.sen_hrd_2 << 16) + (self.sen_hrd_1)
        self.tar_hrd = (self.tar_hrd_3 << 32) + (self.tar_hrd_2 << 16) + (self.tar_hrd_1)

        self.hrd_sen_hex = hex(self.sen_hrd)[2:].zfill(12).upper()
        self.hrd_tar_hex = hex(self.tar_hrd)[2:].zfill(12).upper()

        self.hrd_sen_flip = "".join(reversed([self.hrd_sen_hex[i:i+2] for i in range(0, len(self.hrd_sen_hex), 2)]))
        self.hrd_tar_flip = "".join(reversed([self.hrd_tar_hex[i:i+2] for i in range(0, len(self.hrd_tar_hex), 2)]))

        self.hrd_sen = ":".join(self.hrd_sen_flip[i:i+2] for i in range(0, len(self.hrd_sen_flip), 2))
        self.hrd_tar = ":".join(self.hrd_tar_flip[i:i+2] for i in range(0, len(self.hrd_tar_flip), 2))

        self.sen_add = socket.inet_ntoa (pack("@I", self.sen_pro))
        self.tar_add = socket.inet_ntoa (pack("@I", self.tar_pro))

        self.opr_flip = int.from_bytes(pack('@H',self.opr),"big")

        try:
            self.operation = self.opr_map[self.opr_flip]
        except:
            self.operation = str(self.opr_flip)