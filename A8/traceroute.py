#! /usr/bin/python3

import socket
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, c_ulonglong, c_uint32
from struct import pack
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
        
        self.check_flip = int.from_bytes(pack('@H',self.check),"big")
        self.idd_flip = int.from_bytes(pack('@H',self.idd),"big")
        self.seq_flip = int.from_bytes(pack('@H',self.seq),"big")



def IPv4_pack(target_ip, ttl):
    
    ver = 4
    ihl = 5
    tos = 0
    lenn = 0
    idd = 54321
    flag = 2
    offset = 0
    # ttl = 64
    proto = 1
    check = 0
    src = socket.inet_aton('10.0.2.15')
    dst = socket.inet_aton(target_ip)

    ihl_ver = (ver << 4) + ihl
    flag_off = (flag << 13) + offset

    header = pack('!BBHHHBBH4s4s', ihl_ver, tos, lenn, idd, flag_off, ttl, proto, check, src, dst)

    return header



def ICMP_pack(check, idd, seq):
    
    typee = 8
    code = 0
    # check = 20572
    # idd = 1
    # seq = 9
    data = "TEST".encode()

    header = pack('!BBHHH4s', typee, code, check, idd, seq, data)

    return header



def checksum(msg):
    s = 0
    for i in range(0, len(msg)-1,2):
        w = msg[i+1] + (msg[i] << 8)
        s = s + w

    s = ~s & 0xffff

    return s

try:
    hostname = socket.gethostname()
    interface = socket.gethostbyname(hostname)

    # bind_target = (interface,0)
    bind_target = ('enp0s3',0)

    listen_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(bind_target)

    ttl = 0
    icmp_seq = 0

    print("Tracing route to " + str(sys.argv[1]) + " ...")

except Exception as e:
    print(e)
    exit(1)

while True:
    try:

        request_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        request_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        request_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

        ttl = ttl + 1
        target_ip = sys.argv[1]

        count = 0

        while True:

            count = count + 1

            icmp_id = 5
            icmp_seq = icmp_seq + 1

            ip_h = IPv4_pack(target_ip, ttl)
            icmp_h = ICMP_pack(0, icmp_id, icmp_seq)

            icmp_check = checksum(icmp_h)
            icmp_h = ICMP_pack(icmp_check, icmp_id, icmp_seq)

            packet = ip_h + icmp_h

            send_target = (target_ip, 0)
            request_sock.sendto(packet, send_target)

            mili_start = time.time() * 1000
            default = listen_sock.gettimeout()
            listen_sock.settimeout(1)

            try:
                while True:
                
                    data = listen_sock.recvfrom(65565)[0]

                    mili_end = time.time() * 1000
                    mili_time = mili_end - mili_start
                    mili_time_r = round(mili_time,2)
                    mili_time_f ="{:.2f}".format(mili_time_r)

                    eth = Ether(data[:24])

                    if eth.ethertype == "0800" or eth.ethertype == "IPv4":

                        ip = IPv4(data[14:])
                        icmpp_hstart = ip.hlen + 14

                        if ip.protocol == 1 or ip.protocol == "ICMP":

                            icmpp = ICMP(data[icmpp_hstart:])
                            replay_hstart = icmpp_hstart + 8

                            if icmpp.ttype == 11 and icmpp.code == 0:
                                
                                replay_ip = IPv4(data[replay_hstart:])
                                replay_icmpp_h = replay_ip.hlen + replay_hstart
                                replay_icmpp = ICMP(data[replay_icmpp_h:])
            
                                # time.sleep(1)

                                if count==1:
                                    print("{:>2}".format(ttl) ,end = "  ")

                                print("{:>5}".format(mili_time_f) ,end = " ms  ")

                                if count==3:
                                    print(str(ip.src_add))

                                break

                            if icmpp.ttype == 0 and icmpp.code == 0 and icmpp.idd_flip == icmp_id and icmpp.seq_flip == icmp_seq:

                                # time.sleep(1)

                                if count==1:
                                    print("{:>2}".format(ttl) ,end = "  ")

                                print("{:>5}".format(mili_time_f) ,end = " ms  ")

                                if count==3:
                                    print(str(ip.src_add))
                                    ttl = 30

                                break

            except Exception:
                if count==1:
                    print("{:>2}".format(ttl) ,end = "  ")

                print("{:>5}".format("*") ,end="     ")

                if count==3:
                    print("Request timed out")

            listen_sock.settimeout(default)

            if count == 3:
                break

        if ttl == 30:
            break

    except KeyboardInterrupt:
        print("Exit")
        exit(1)

    except Exception as e:
        print(e)
        exit(1)

try:

    print("Trace complete")

except Exception as e:
    print(e)
    exit(1)
