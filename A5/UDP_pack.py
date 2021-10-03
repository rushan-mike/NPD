#! /usr/bin/python3
import socket
from struct import pack

def UDP():

    src_port = #c_ushort     #16
    dst_port = #c_ushort     #16
    lenn = #c_ushort         #16
    summ = #c_ushort         #16

    header = pack('!HHHH', src_port, dst_port, lenn, summ)

    return header