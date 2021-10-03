#! /usr/bin/python3

import socket
import threading
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, c_ulonglong, c_uint32
from struct import pack
import netifaces
import time
import sys

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



class IPv4(Structure):
    _fields_= [
        # ("ver", c_ubyte, 4),      #4
        # ("ihl", c_ubyte, 4),      #4
        ("iv", c_ubyte),            #8
        ("tos", c_ubyte),           #8
        ("len", c_ushort),          #16
        ("id", c_ushort),           #16
        ("flag", c_ubyte, 3),       #3
        ("offset", c_ushort, 13),   #13
        ("ttl", c_ubyte),           #8
        ("proto", c_ubyte),         #8
        ("summ", c_ushort),         #16
        ("src", c_uint32),          #32
        ("dst", c_uint32)           #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):

        self.proto_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_add = socket.inet_ntoa (pack("@I", self.src))
        self.dst_add = socket.inet_ntoa (pack("@I", self.dst))

        self.ver = self.iv >> 4
        self.ihl = self.iv & 15 

        self.hlen = self.ihl * 4

        try:
            self.protocol = self.proto_map[self.proto]
        except:
            self.protocol = str(self.proto)


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
        
        self.check_flip = hex(int.from_bytes(pack('@H',self.check),"big"))
        self.idd_flip = int.from_bytes(pack('@H',self.idd),"big")
        self.seq_flip = int.from_bytes(pack('@H',self.seq),"big")



def forward(interface):
    try:
        bind_target = (interface,0)

        listen_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(bind_target)

        print("Forwarding Active on " + interface + " ... ")

    except Exception as e:
        print(e)
        exit(1)

    while True:
        try:

            data = listen_sock.recvfrom(65565)[0]
            ip = IPv4(data[14:])
            # print(ip.src_add + " ->> " + ip.dst_add + " : " + ip.protocol, end=" ")
            hstart = ip.hlen + 14
            pad = "000000000000".encode()

            if ip.protocol == 1 or ip.protocol == "ICMP":
            
                icmpp = ICMP(data[hstart:])

            elif ip.protocol == 6 or ip.protocol == "TCP":

                tcpp = TCP(data[hstart:]+pad)
                # print(str(tcpp.src_port_flip) + " ->> " + str(tcpp.dst_port_flip))

            elif ip.protocol == 17 or ip.protocol == "UDP":

                udpp = UDP(data[hstart:])
                # print(str(udpp.src_port_flip) + " ->> " + str(udpp.dst_port_flip))

            packet = data[14:]

            forward_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            forward_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # forward_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

            send_target = (ip.dst_add, 0)
            forward_sock.sendto(packet, send_target)

        except KeyboardInterrupt:
            print("Exit")
            exit(1)

        except Exception as e:
            print(e)
            exit(1)

try:

    inter = 0
    inter_all = netifaces.interfaces()

    while inter<len(inter_all):
        
        if inter_all[inter] != "lo" and inter != len(inter_all)-1:
            inter_name = inter_all[inter]
            threading.Thread(target=forward, args=(inter_name,), daemon=True).start()

        if inter == len(inter_all)-1:
            inter_last = inter_all[inter]

        inter = inter + 1

    forward(inter_last)

except Exception as e:
    print(e)
    exit(1)