#! /usr/bin/python3
try:
    # inpath = ("ascii.txt")
    inpath=input("Enter relative file path or absalute file path of input:")
    outpath=input("Enter relative file path or absalute file path for output:")

    if not outpath: outpath=(inpath+"_Hexdump.txt")
    infile = open(inpath,"rb")
    outfile = open(outpath,"x")

    bidump = infile.read()
    hexdump = bidump.hex()

    hc, off, pric, hexs, hexg, chag, chadump = 0, 0, 0, 0, "", "", ""

    while hc<=len(hexdump)+32:

        if not hexdump[hc:hc+2]:
            hexp, cha = "  ", ""
        else:
            hexp=str(hexdump[hc:hc+2])
            if 32<=int(hexp,16)<=126:   cha=chr(int(hexp,16))
            else:   cha=chr(46)

        hexg, chag, hexs, pric, hc = hexg+hexp, chag+cha, hexs+1, pric+1, hc+2

        if hexs==2:
            hexg, hexs = hexg+" ", 0

        if pric==16:
            print("{:07x}".format(off)+"0:\t"+hexg+"\t"+chag)
            outfile.write("{:07x}".format(off)+"0:\t"+hexg+"\t"+chag+"\n")
            pric, hexg, chag, off = 0, "", "", off+1

    infile.close()
    outfile.close()

except FileNotFoundError:
    print("usage : program_name [infile] [outfile]")
    # print("No such file or directory! ")