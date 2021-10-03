#! /usr/bin/python3

import socket
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, c_ulonglong, c_uint32
from struct import pack

def IPv4_pack():
    
    ver = 4
    ihl = 5
    tos = 0
    lenn = 0
    idd = 54321
    flag = 2
    offset = 0
    ttl = 64
    proto = 1
    check = 0
    src = socket.inet_aton('10.0.2.15')
    dst = socket.inet_aton('192.168.1.68')

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


sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

icmp_id = 5
icmp_seq = 1

ip_h = IPv4_pack()
icmp_h = ICMP_pack(0, icmp_id, icmp_seq)

icmp_check = checksum(icmp_h)
icmp_h = ICMP_pack(icmp_check, icmp_id, icmp_seq)

packet = ip_h + icmp_h

send_target = ('192.168.1.68', 0)
sock.sendto(packet, send_target)
