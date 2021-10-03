#! /usr/bin/python3

import socket
from ctypes import Structure, c_ubyte, c_ushort, c_ulong
from struct import pack


class IPv4(Structure):
    _fields_= [
        ("version", c_ubyte, 4),    #4
        ("ihl", c_ubyte, 4),        #4
        ("tos", c_ubyte),           #8
        ("len", c_ushort),          #16
        ("id", c_ushort),           #16
        ("flag", c_ubyte, 3),       #3
        ("offset", c_ushort, 13),   #13
        ("ttl", c_ubyte),           #8
        ("protocol_num", c_ubyte),  #8
        ("sum", c_ushort),          #16
        ("src", c_ulong),           #32
        ("dst", c_ulong)            #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        pass
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_address = socket.inet_ntoa (pack("@I", self.src))
        self.dst_address = socket.inet_ntoa (pack("@I", self.dst))

        #human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

# ETH_P_IP = 0x0800

try:
    hostname = socket.gethostname()
    interface = socket.gethostbyname(hostname)
    target = (interface,0)
    
    #sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
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
        print(ip.src_address + "\t ->>\t" + ip.dst_address + "\t\t: " + ip.protocol)

    except KeyboardInterrupt:
        print("Exit")
        exit(1)

    except Exception as e:
        print(e)
        exit(1)
