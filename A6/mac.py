#! /usr/bin/python3
import socket
from struct import pack

mac = "11:BB:CC:DD:EE:FF"

mac_bin = bin(int(mac.replace(':', ''), 16))[2:].zfill(48)

mac_bin_t = " ".join(mac_bin[i:i+8] for i in range(0, len(mac_bin), 8))

print(mac_bin_t)
# print(mac_bin)

mac_hex = hex(int(mac_bin, 2))[2:].upper()

mac_hex_t = ":".join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))

print(mac_hex_t)