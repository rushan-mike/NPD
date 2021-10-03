#! /usr/bin/python3

import os
import struct
import socket
import threading
from fcntl import ioctl
from cryptography.fernet import Fernet

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



def client_send(client):
    while True:
        client_data = os.read(fd, 1600)
        enc_client_data = encrypt_message(client_data)
        client.send(enc_client_data)
        # client_data = input()
        # client.send(client_data.encode())


def client_receive(client):
    while True:
        server_data = client.recv(2048)
        dec_server_data = decrypt_message(server_data)
        os.write(fd, dec_server_data)
        # print (server_data.decode())


fd = tun_open('asa0')

# server_name = socket.gethostname()
# server_ip = socket.gethostbyname(server_name)
server_ip = '192.168.1.2'
port = 9090

target = (server_ip,port)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

    client.connect(target)

    while True:

        client_T = threading.Thread(target=client_receive, args=(client,), daemon=True)
        client_T.start()
        client_send(client)