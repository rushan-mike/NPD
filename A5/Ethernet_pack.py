#! /usr/bin/python3
import socket
from struct import pack

def Ether():

    # pre = #c_ulonglong, 56     #56
    # deli = #c_ubyte            #8
    mac_ds = #c_ulonglong, 48    #48
    mac_sr = #c_ulonglong, 48    #48
    # tag = #c_ulong             #32
    etype = #c_ushort            #16
    # pload = #c_ulonglong       #512 (46-1500 octets)
    # check = #c_ulong           #32
    # gap_1 = #c_ulonglong       #64
    # gap_2 = #c_ulong           #32

    mac_dst = bin(int(mac_ds.replace(':', ''), 16))
    mac_src = bin(int(mac_sr.replace(':', ''), 16))

    mac_dst_f = mac_dst >> 32
    mac_dst_n = (mac_dst >> 16) - (mac_dst_f << 16)
    mac_dst_l = mac_dst - ((mac_dst >> 16) << 16)

    mac_src_f = mac_src >> 32
    mac_src_n = (mac_src >> 16) - (mac_src_f << 16)
    mac_src_l = mac_src - ((mac_src >> 16) << 16)

    header = pack('!HHHHHHH', mac_dst_f, mac_dst_n, mac_dst_l, mac_src_f, mac_src_n, mac_src_l, etype)

    return header