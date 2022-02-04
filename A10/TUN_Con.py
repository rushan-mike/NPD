#! /usr/bin/python3

import os
import sys
import hmac
import socket
import hashlib
import threading
import netifaces
from struct import pack
from fcntl import ioctl
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from ctypes import Structure, c_ubyte, c_ushort, c_ulong, c_ulonglong, c_uint32

# ETH_P_ALL = 0x0003
# ETH_P_IP  = 0x0800
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
# TUNMODE   = IFF_TUN

class IPv4(Structure):
    _fields_= [
        # ("ver", c_ubyte, 4),      #4
        # ("ihl", c_ubyte, 4),      #4
        ("iv", c_ubyte),            #8
        ("tos", c_ubyte),           #8
        ("len", c_ushort),          #16
        ("id", c_ushort),           #16
        ("flag", c_ubyte, 3),       #3
        ("offset", c_ushort, 13),   #13
        ("ttl", c_ubyte),           #8
        ("proto", c_ubyte),         #8
        ("summ", c_ushort),         #16
        ("src", c_uint32),          #32
        ("dst", c_uint32)           #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):

        self.proto_map = {1:"ICMP", 6:"TCP", 17:"UDP", 50:"ESP", 51:"AH"}

        self.src_add = socket.inet_ntoa (pack("@I", self.src))
        self.dst_add = socket.inet_ntoa (pack("@I", self.dst))

        self.ver = self.iv >> 4
        self.ihl = self.iv & 15 

        self.hlen = self.ihl * 4

        try:
            self.protocol = self.proto_map[self.proto]
        except:
            self.protocol = str(self.proto)


class ESP(Structure):
    _fields_= [
        ("spi", c_ubyte*4),           #32
        ("snum", c_ubyte*4),          #32
        ("enc_payload", c_ubyte*258), #258*8
        # ("payload", c_ubyte*256),   #256*8
        # ("padlen", c_ubyte),        #8
        # ("nextt", c_ubyte),         #8
        ("icv", c_ubyte*4)            #32
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy (socket_buffer)

    def __init__(self, socket_buffer=None):
        pass


def IPv4_pack(target_ip, interface_ip):
    
    ver = 4
    ihl = 5
    tos = 0
    lenn = 0
    idd = 54321
    flag = 2
    offset = 0
    ttl = 64
    proto = 50
    check = 0
    src = socket.inet_aton(interface_ip)
    dst = socket.inet_aton(target_ip)

    ihl_ver = (ver << 4) + ihl
    flag_off = (flag << 13) + offset

    header = pack('!BBHHHBBH4s4s', ihl_ver, tos, lenn, idd, flag_off, ttl, proto, check, src, dst)

    return header


def ESP_pack(data, seq_num):
    
    spi = 256 #c_ulong          #32
    # seq_num = 0 #c_ulong      #32
    # payload = #c_ubyte*256    #256*8
    # padlen = #c_ubyte         #8
    nextt = 4 #c_ubyte          #8
    # icv = #c_ulong            #32

    datalen = len(data)
    padlen = 256 - datalen
    
    if datalen < 256 :
        payload = data + "\0".encode() * padlen
        
    print(payload, end="\n\n")
    print(len(payload), end="\n\n")

    payload_tob_enc = payload + str(padlen).encode() + str(nextt).encode()
    print(payload_tob_enc, end="\n\n")
    print(len(payload_tob_enc), end="\n\n")
    enc_payload = encrypt_message_AES(payload_tob_enc)
    print(enc_payload, end="\n\n")
    print(len(enc_payload), end="\n\n")

    icv_data = str(spi).encode() + str(seq_num).encode() + payload_tob_enc
    print(icv_data, end="\n\n")
    print(len(icv_data), end="\n\n")
    icv = ICV(icv_data)
    print(icv, end="\n\n")
    print(len(icv), end="\n\n")

    header = pack('!LL258BL', spi, seq_num, enc_payload, icv)

    return header


def ESP_unpack(packet):
    
    esp = ESP(packet)
    dec_payload = decrypt_message(esp.enc_payload)
    
    icv_data = str(esp.spi).encode() + str(esp.snum).encode() + dec_payload
    check = ICV_check(icv_data, esp.icv)

    if check == True:
        
        payload = dec_payload[:256]
        padlen_next = dec_payload[256:]
        
        padlen = padlen_next[:8]
        nextt = padlen_next[8:]
        
        paylen = 256 - int(padlen.decode())
        data = payload[:paylen]
    else:
        data = 0

    return data, check


def tun_send(target_ip, interface_ip):
    # try:

    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    forward_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    forward_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    seq_num = 0
    data_length = 1600

    while True:

        send_data = os.read(fd, data_length)
        seq_num = seq_num + 1
        
        if 0 < len(send_data) <= 256 :

            ip_h = IPv4_pack(target_ip, interface_ip)
            esp_h = ESP_pack(send_data, seq_num)

            packet = ip_h + esp_h

            send_target = (target_ip, 0)
            forward_sock.sendto(packet, send_target)

    # except Exception as e:
    #     print(e)
    #     exit(1)


def tun_receive(interface):
    # try: 
    bind_target = (interface,0)

    listen_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(bind_target)

    while True:

        receive_data = listen_sock.recvfrom(65565)[0]

        ip = IPv4(receive_data[14:])
        hstart = ip.hlen + 14

        if ip.protocol == 50 or ip.protocol == "ESP":

            esp_data = receive_data[hstart:]
            data, check = ESP_unpack(esp_data)

            if check == True:
                os.write(fd, data)

    # except Exception as e:
    #     print(e)
    #     exit(1)


def tun_open(devname):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = pack('16sH',devname.encode(), IFF_TUN | IFF_NO_PI)
    ifs = ioctl(fd, TUNSETIFF , ifr)
    return fd


def encrypt_message_AES(message):
    key = b'Sixteen byte key'
    iv = b'Sixteen byte iv_'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message


def decrypt_message_AES(encrypted_message):
    key = b'Sixteen byte key'
    iv = b'Sixteen byte iv_'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message


def encrypt_message(message):
    key = "v30nE9iDBSlWlIzViAiqmgvIypz0v4qjGmiYHbNoXn8="
    f = Fernet(key)
    encrypted_message = f.encrypt(message)
    return encrypted_message


def decrypt_message(encrypted_message):
    key = "v30nE9iDBSlWlIzViAiqmgvIypz0v4qjGmiYHbNoXn8="
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message


def ICV(message):
    key= "v30nE9iDBSlWlIzViAiqmgvIypz0v4qjGmiYHbNoXn8="
    message_digest = hmac.digest(key.encode(), message, hashlib.sha3_256)
    return message_digest


def ICV_check(message, digest):
    key= "v30nE9iDBSlWlIzViAiqmgvIypz0v4qjGmiYHbNoXn8="
    message_digest = hmac.digest(key.encode(), message, hashlib.sha3_256)
    check = hmac.compare_digest(message_digest, digest)
    return check

fd = tun_open('asa0')

# try:
inter_all = netifaces.interfaces()

target_ip = sys.argv[1]
# interface = sys.argv[2]

# target_ip = '192.168.1.1'
interface = 'enp0s3'

interface_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

threading.Thread(target=tun_send, args=(target_ip, interface_ip), daemon=True).start()
tun_receive(interface)

# except Exception as e:
#     print(e)
#     exit(1)