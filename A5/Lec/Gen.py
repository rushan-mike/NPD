#! /usr/bin/python3
import socket
from struct import pack

# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0      # kernel will fil the correct checksum
ip_id = 54321       # ID of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = 6
ip_check = 0        # kernel will fill the correct checksum
ip_saddr = socket.inet_aton('192.168.12.133')   # spoof the source ip address if you want to
ip_daddr = socket.inet_aton('192.168.12.132')

ip_ihl_ver = (ip_ver << 4) + ip_ihl

# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)