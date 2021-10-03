#! /usr/bin/python3

import socket
import threading

def server_send(client_conn):
    while True:
        server_data = input()
        client_conn.send(server_data.encode())

def server_receive(client_conn):
    while True:
        client_data = client_conn.recv(1024)
        print (client_data.decode())

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