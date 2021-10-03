#! /usr/bin/python3
with open("c:/Users/Michael/Downloads/ascii2.txt","rb") as openfile:
    hexline=""
    a=0
    c=0
    characters=""
    while True:
        readf=openfile.read(2)
        if len(readf)==0:  
            break
        hexstring=readf.hex()
        hexspace=hexstring+" "
        hexline=hexline+hexspace
        char=chr(int(hexstring[0:2],16))+chr(int(hexstring[2:4],16))
        characters=characters+char
        a=a+1
        if a==8:
            print("{:07x}".format(c)+"0\t"+hexline+"\t"+characters)
            c=c+1
            hexline=""
            characters=""
            a=0