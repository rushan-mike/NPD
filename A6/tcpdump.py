#! /usr/bin/python3

import socket
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, c_uint32
from struct import pack


class IPv4(Structure):
    _fields_= [
        ("ver", c_ubyte, 4),        #4
        ("ihl", c_ubyte, 4),        #4
        ("tos", c_ubyte),           #8
        ("len", c_ushort),          #16
        ("id", c_ushort),           #16
        ("flag", c_ubyte, 3),       #3
        ("offset", c_ushort, 13),   #13
        ("ttl", c_ubyte),           #8
        ("proto", c_ubyte),         #8
        ("sum", c_ushort),          #16
        ("src", c_uint32),          #32
        ("dst", c_uint32)           #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        pass

        self.proto_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_add = socket.inet_ntoa (pack("@I", self.src))
        self.dst_add = socket.inet_ntoa (pack("@I", self.dst))

        try:
            self.protocol = self.proto_map[self.proto]
        except:
            self.protocol = str(self.proto)

# ETH_P_IP = 0x0800
ETH_P_IP = 0x0003

try:
    hostname = socket.gethostname()
    interface = socket.gethostbyname(hostname)
    target = ('enp0s3',0)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(target)

except Exception as e:
    print(e)
    exit(1)

while True:
    try:
        data = sock.recvfrom(65565)[0]
        ip = IPv4(data[14:])
        print(ip.src_add + "\t ->>\t" + ip.dst_add + "\t\t: " + ip.proto)

    except KeyboardInterrupt:
        print("Exit")
        exit(1)

    except Exception as e:
        print(e)
        exit(1)
