#! /usr/bin/python3
import socket
from struct import pack

def Ether():
    
    # pre = #c_ulonglong, 56     #56
    # deli = #c_ubyte            #8
    mac_ds = #c_ulonglong, 48    #48
    mac_sr = #c_ulonglong, 48    #48
    # tag = #c_ulong             #32
    etype = #c_ushort            #16
    # pload = #c_ulonglong       #512 (46-1500 octets)
    # check = #c_ulong           #32
    # gap_1 = #c_ulonglong       #64
    # gap_2 = #c_ulong           #32

    mac_dst = bin(int(mac_ds.replace(':', ''), 16))
    mac_src = bin(int(mac_sr.replace(':', ''), 16))

    mac_dst_f = mac_dst >> 32
    mac_dst_n = (mac_dst >> 16) - (mac_dst_f << 16)
    mac_dst_l = mac_dst - ((mac_dst >> 16) << 16)

    mac_src_f = mac_src >> 32
    mac_src_n = (mac_src >> 16) - (mac_src_f << 16)
    mac_src_l = mac_src - ((mac_src >> 16) << 16)

    header = pack('!HHHHHHH', mac_dst_f, mac_dst_n, mac_dst_l, mac_src_f, mac_src_n, mac_src_l, etype)

    return header



def ARP():
    
    hrd_typ = #c_ushort          #16
    pro_typ = #c_ushort          #16
    hrd_len = #c_ubyte           #8
    pro_len = #c_ubyte           #8
    opr = #c_ushort              #16
    sen_hrd = #c_ulonglong, 48   #48
    sen_pro = #c_ulong           #32
    tar_hrd = #c_ulonglong, 48   #48
    tar_pro = #c_ulong           #32

    sen_hrd_f = sen_hrd >> 32
    sen_hrd_n = (sen_hrd >> 16) - (sen_hrd_f << 16)
    sen_hrd_l = sen_hrd - ((sen_hrd >> 16) << 16)

    tar_hrd_f = tar_hrd >> 32
    tar_hrd_n = (tar_hrd >> 16) - (tar_hrd_f << 16)
    tar_hrd_l = tar_hrd - ((tar_hrd >> 16) << 16)

    header = pack('!HHBBHHHHLHHHL', hrd_typ, pro_typ, hrd_len, pro_len, opr, sen_hrd_f, sen_hrd_n, sen_hrd_l, sen_pro, tar_hrd_f, tar_hrd_n, tar_hrd_l, tar_pro)

    return header



def IPv4():

    ver = 4
    ihl = 5
    tos = 0
    lenn = 0
    idd = 54321
    flag = 0
    offset = 0
    ttl = 64
    proto = 6
    check = 0
    src = socket.inet_aton('192.168.10.12')
    dst = socket.inet_aton('192.168.10.12')

    ihl_ver = (ver << 4) + ihl
    flag_off = (flag << 13) + offset

    header = pack('!BBHHHBBH4s4s', ihl_ver, tos, lenn, idd, flag_off, ttl, proto, check, src, dst)

    return header



def IPv6():
    
    version = #c_ubyte, 4        #4
    traffic = #c_ubyte           #8
    flow_label = #c_ulong, 20    #20
    lenn = #c_ushort             #16
    nextt = #c_ubyte             #8
    hop = #c_ubyte               #8
    src_add =                    #128
    dst_add =                    #128

    traffic_ver = (version << 4) + (traffic >> 4)
    traffic_flow = (traffic - ((traffic >> 4) << 4)) + (flow_label >> 20)
    flow_label_end = flow_label - ((flow_label >> 20) << 20)

    src = socket.inet_pton(socket.AF_INET6, src_add)
    dst = socket.inet_pton(socket.AF_INET6, dst_add)

    src_1 = src >> 64
    src_2 = src - ((src >> 64) << 64)

    dst_1 = dst >> 64
    dst_2 = dst - ((dst >> 64) << 64)

    header = pack('!BBHHBBQQQQ', traffic_ver, traffic_flow, flow_label_end, lenn, nextt, hop, src_1, src_2, dst_1, dst_2)

    return header



def TCP():
    
    src_port = #c_ushort     #16
    dst_port = #c_ushort     #16
    seq_num = #c_ulong       #32
    ack_num = #c_ulong       #32
    offset = #c_ubyte, 4     #4
    res = #c_ubyte, 3        #3
    flag = #c_ushort, 9      #9
    win_size = #c_ushort     #16
    summ = #c_ushort         #16
    urg_point = #c_ushort    #16

    flag_offset = offset + res + flag

    header = pack('!HHLLHHHH', src_port, dst_port, seq_num, ack_num, flag_offset, win_size, summ, urg_point)

    return header



def UDP():
    
    src_port = #c_ushort     #16
    dst_port = #c_ushort     #16
    lenn = #c_ushort         #16
    summ = #c_ushort         #16

    header = pack('!HHHH', src_port, dst_port, lenn, summ)

    return header



def ICMP():
    
    typee = #c_ubyte    #8
    code = #c_ubyte     #8
    check = #c_ushort   #16
    idd = #c_ushort     #16
    seq = #c_ushort     #16


    header = pack('!BBHHH', typee, code, check, idd, seq)

    return header



