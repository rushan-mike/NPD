#! /usr/bin/python3
import socket
from struct import pack

def TCP():

    src_port = #c_ushort     #16
    dst_port = #c_ushort     #16
    seq_num = #c_ulong       #32
    ack_num = #c_ulong       #32
    offset = #c_ubyte, 4     #4
    res = #c_ubyte, 3        #3
    flag = #c_ushort, 9      #9
    win_size = #c_ushort     #16
    summ = #c_ushort         #16
    urg_point = #c_ushort    #16

    flag_offset = offset + res + flag

    header = pack('!HHLLHHHH', src_port, dst_port, seq_num, ack_num, flag_offset, win_size, summ, urg_point)

    return header