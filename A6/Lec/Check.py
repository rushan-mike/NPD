#! /usr/bin/python3
import socket

def checksum(msg):
    s = 0
    for i in range(0, len(msg)-3,4):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8) + (ord(msg[i+2]) << 16) + (ord(msg[i+3]) << 24)
        s = s + w

    s = (s>>32) + (s & 0xffffffff)
    s = s + (s >> 32)
    s = ~s & 0xffffffff

    return s

ETH_P_IP = 0x0800

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sock.bind(('ens33',0))

data = sock.recv(65565)[0]