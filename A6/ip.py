#! /usr/bin/python3
import socket
from struct import pack, unpack

ip = socket.inet_aton('255.240.15.0')

print(ip)

netip = pack('!4s',ip)

print(netip)

netByteodr = unpack('>4B',netip)

print(netByteodr)