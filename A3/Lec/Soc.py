#! /usr/bin/python3

import socket

host = "www.google.com"
port = 80

sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

add=(host,port)

sock.connect(add)

sock.send("GET / HTTP/1.1\r\n\r\n".encode())

data = sock.recv(4096)

print (data.decode("utf-8"))