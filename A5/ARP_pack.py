import socket
from struct import pack

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