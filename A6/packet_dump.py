#! /usr/bin/python3

import socket
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, c_ulonglong, c_uint32
from struct import pack
import time

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



try:
    hostname = socket.gethostname()
    interface = socket.gethostbyname(hostname)

    # target = (interface,0)
    target = ('enp0s3',0)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(target)

except Exception as e:
    print(e)
    exit(1)    

while True:
    try:

        data = sock.recvfrom(65565)[0]
        eth = Ether(data[:24])
        pad = "000000000000".encode()
        
        print (time.strftime("%H:%M:%S"), end=" ")
        print(eth.src_mac + " ->> " + eth.dst_mac + " : " + eth.ethertype, end=" ")

        if eth.ethertype == "0806" or eth.ethertype == " ARP":

            arp = ARP(data[14:]+pad)

            if arp.operation == 1 or arp.operation == "request":

                print("(" + arp.operation + ")")#, end=" ")
                # print(arp.tar_add + " tell " + arp.sen_add)

            elif arp.operation == 2 or arp.operation == "reply":

                print("(" + arp.operation + ")")#, end=" ")
                # print(arp.tar_add + " is-at " + arp.hrd_tar)

        elif eth.ethertype == "0800" or eth.ethertype == "IPv4":

            ip = IPv4(data[14:])
        
            print(ip.src_add + " ->> " + ip.dst_add + " : " + ip.protocol, end=" ")

            hstart = ip.hlen + 14

            if ip.protocol == 1 or ip.protocol == "ICMP":

                icmpp = ICMP(data[hstart:])
                print("Type:" + str(icmpp.ttype) + " Code:" + str(icmpp.code), end=" ")
                print("CheckSum:" + str(icmpp.check_flip), end=" ")
                print("ID:" + str(icmpp.idd_flip) + " Seq:" + str(icmpp.seq_flip))

            elif ip.protocol == 6 or ip.protocol == "TCP":

                tcpp = TCP(data[hstart:]+pad)
                print(str(tcpp.src_port_flip) + " ->> " + str(tcpp.dst_port_flip))#, end=" ")
                # print("Flag:" + tcpp.flagg, end=" ")
                # print("Seq:" + str(tcpp.seq_num_flip) + " Ack:" + str(tcpp.ack_num_flip))

            elif ip.protocol == 17 or ip.protocol == "UDP":

                udpp = UDP(data[hstart:])
                print(str(udpp.src_port_flip) + " ->> " + str(udpp.dst_port_flip))

            else:
                print("")

        elif eth.ethertype == "86DD" or eth.ethertype == "IPv6":

            ip6 = IPv6(data[14:])
    
            print("")

        else:
            print("")


    except KeyboardInterrupt:
        print("Exit")
        exit(1)

    except Exception as e:
        print(e)
        exit(1)
