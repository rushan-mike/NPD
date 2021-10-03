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



def server_send(client_conn):
    while True:
        server_data = os.read(fd, 1600)
        enc_server_data = encrypt_message(server_data)
        client_conn.send(enc_server_data)
        # server_data = input()
        # client_conn.send(server_data.encode())


def server_receive(client_conn):
    while True:
        client_data = client_conn.recv(2048)
        dec_client_data = decrypt_message(client_data)
        os.write(fd, dec_client_data)
        # print (client_data.decode())


fd = tun_open('asa0')

server_name = socket.gethostname()
server_ip = socket.gethostbyname(server_name) 
port = 9090

target = (server_ip,port)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

    server.bind(target)
    server.listen(1)
    client_conn, client_addr = server.accept()

    while client_conn:

        server_T = threading.Thread(target=server_receive, args=(client_conn,), daemon=True)
        server_T.start()
        server_send(client_conn)