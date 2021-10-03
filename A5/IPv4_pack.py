#! /usr/bin/python3
import socket
from struct import pack

def IPv4():

    ver = 4
    ihl = 5
    tos = 0
    lenn = 0
    idd = 54321
    flag = 0
    offset = 0
    ttl = 64
    proto = 6
    check = 0
    src = socket.inet_aton('192.168.10.12')
    dst = socket.inet_aton('192.168.10.12')

    ihl_ver = (ver << 4) + ihl
    flag_off = (flag << 13) + offset

    header = pack('!BBHHHBBH4s4s', ihl_ver, tos, lenn, idd, flag_off, ttl, proto, check, src, dst)

    return header