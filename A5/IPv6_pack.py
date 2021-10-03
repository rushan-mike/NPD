#! /usr/bin/python3
import socket
from struct import pack

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

    header = pcak('!BBHHBBQQQQ', traffic_ver, traffic_flow, flow_label_end, lenn, nextt, hop, src_1, src_2, dst_1, dst_2)

    return header