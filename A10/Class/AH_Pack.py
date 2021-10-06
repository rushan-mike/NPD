#! /usr/bin/python3
import socket
from struct import pack

def AH():

    nextt = #c_ubyte        #8
    plen = #c_ubyte         #8
    res = #c_ushort         #16
    spi = #c_ulong          #32
    snum = #c_ulong         #32
    icv = #c_ulong          #32

    header = pack('!BBHLLL', nextt, plen, res, spi, snum, icv)

    return header