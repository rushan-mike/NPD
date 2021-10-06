#! /usr/bin/python3
import socket
from struct import pack

def ESP():

    spi = #c_ulong          #32
    snum = #c_ulong         #32
    payload = #c_ubyte*256  #256*8
    pdlen = #c_ubyte        #8
    nextt = #c_ubyte        #8
    icv = #c_ulong          #32
    


    header = pack('!LL256BBBL', spi, snum, payload, pdlen, nextt, icv)

    return header