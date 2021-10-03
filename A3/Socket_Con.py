#! /usr/bin/python3

import socket
import threading
import sys

try:
    port = 9090

    def server_send(client_conn):
        while True:
            server_data = input()
            client_conn.send(server_data.encode())

    def server_receive(client_conn):
        while True:
            try:
                client_data = client_conn.recv(1024)
                print (client_data.decode())
            except ConnectionResetError:
                    sys.exit(0)

    def client_send(client):
        while True:
            client_data = input()
            client.send(client_data.encode())

    def client_receive(client):
        while True:
            try:
                server_data = client.recv(1024)
                print (server_data.decode())
            except ConnectionResetError:
                    sys.exit(0)

    if sys.argv[1] == "1":

        server_name = socket.gethostname()
        server_ip = socket.gethostbyname(server_name) 
        target = (server_ip,port)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

            server.bind(target)
            server.listen(1)
            client_conn, client_addr = server.accept()

            while client_conn:
                server_T = threading.Thread(target=server_receive, args=(client_conn,), daemon=True)
                server_T.start()
                server_send(client_conn)

    elif sys.argv[1] == "2":

        server_name = socket.gethostname()
        server_ip = socket.gethostbyname(server_name)
        target = (server_ip,port)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

            client.connect(target)

            while True:
                client_T = threading.Thread(target=client_receive, args=(client,), daemon=True)
                client_T.start()
                client_send(client)


except:
    print("Enter 1 for server or 2 for client")