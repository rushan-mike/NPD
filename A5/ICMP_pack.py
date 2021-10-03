#! /usr/bin/python3
import socket
from struct import pack

def ICMP():

    typee = #c_ubyte    #8
    code = #c_ubyte     #8
    check = #c_ushort   #16
    idd = #c_ushort     #16
    seq = #c_ushort     #16


    header = pack('!BBHHH', typee, code, check, idd, seq)

    return header