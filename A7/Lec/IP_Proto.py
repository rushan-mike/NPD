#! /usr/bin/python3
import socket
from struct import pack

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# ---- IP Header
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# ip header fields
ver = 4
ihl = 5
tos = 0
lenn = 0        # kernel will fil the correct checksum
idd = 54321     # ID of this packet
flag = 0
offset = 0
ttl = 255
proto = 6
check = 0       # kernel will fill the correct checksum
src = socket.inet_aton('192.168.10.12')     # spoof the source ip address if you want to
dst = socket.inet_aton('192.168.10.12')

ihl_ver = (ver << 4) + ihl
flag_off = (flag << 13) + offset

# the ! in the pack format string means network order
header = pack('!BBHHHBBH4s4s', ihl_ver, tos, lenn, idd, flag_off, ttl, proto, check, src, dst)

packet = header + data 

target = ('192.168.10.12',0)

sock.sendto(packet, target)