#! /usr/bin/python3

import struct
import os
from fcntl import ioctl

# ETH_P_ALL = 0x0003
# ETH_P_IP  = 0x0800
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
TUNMODE   = IFF_TUN

def tun_open(devname):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH',devname.encode(), IFF_TUN | IFF_NO_PI)
    ifs = ioctl(fd, TUNSETIFF , ifr)
    return fd

fd = tun_open('asa0')

while True:
    data = os.read(fd, 1600)
    print(data)