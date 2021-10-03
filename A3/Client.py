#! /usr/bin/python3

import socket
import threading

def client_send(client):
    while True:
        client_data = input()
        client.send(client_data.encode())

def client_receive(client):
    while True:
        server_data = client.recv(1024)
        print (server_data.decode())


server_name = socket.gethostname()
server_ip = socket.gethostbyname(server_name)
port = 9090

target = (server_ip,port)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

    client.connect(target)

    while True:

        client_T = threading.Thread(target=client_receive, args=(client,), daemon=True)

        client_T.start()

        client_send(client)