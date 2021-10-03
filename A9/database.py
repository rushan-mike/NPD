#! /usr/bin/python3

import sqlite3
import sys
import itertools


def check_db():
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_table'")
    statement = c.fetchone()[0]

    print(statement)

    conn.commit()
    conn.close()


def drop_table():
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("DROP TABLE IF EXISTS ip_table")
    
    conn.commit()
    conn.close()


def create_table():

    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS ip_table( 
                ipsrc NAME,
                ipdst NAME,
                ipprt NAME,
                srcp NAME,
                dstp NAME,
                rule NAME
    )""")
    
    conn.commit()
    conn.close()


def insert_record(ipsrc, ipdst, ipprt, srcp, dstp, rule):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("INSERT INTO ip_table VALUES (?,?,?,?,?,?)", (ipsrc, ipdst, ipprt, srcp, dstp, rule))
    # ip -> string
    # port -> string
    # traffic -> string
    
    conn.commit()
    conn.close()


def update_record(rowid, rule):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("UPDATE ip_table SET rule = (?) WHERE rowid = (?)",(rule, rowid)) 

    conn.commit()
    conn.close()


def delete_record(rid):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("DELETE FROM ip_table WHERE rowid = (?)", str(rid))
    # rowid -> int
    # rid -> string

    conn.commit()
    conn.close()


def check_table(ipsrc, ipdst, ipprt, srcp, dstp):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM ip_table WHERE ipsrc = (?) AND ipdst = (?) AND ipprt = (?) AND srcp = (?) AND dstp = (?)", (ipsrc, ipdst, ipprt, srcp, dstp,))
    count = c.fetchone()[0]

    conn.commit()
    conn.close()

    if count == 1:

        conn = sqlite3.connect('iptables.db')
        c = conn.cursor()

        c.execute("SELECT rowid FROM ip_table WHERE ipsrc = (?) AND ipdst = (?) AND ipprt = (?) AND srcp = (?) AND dstp = (?)", (ipsrc, ipdst, ipprt, srcp, dstp,))
        rows = c.fetchall()
        # port -> string

        for row in rows:
            rowid = row[0]

        conn.commit()
        conn.close()

        return rowid

    else:
        return "noid"


def display_table():
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()
    
    c.execute("SELECT rowid, * FROM ip_table")
    records = c.fetchall()

    # print("Row-ID  " + "Source-IP  " + "Destination-IP  " + "Protocol-IP  " + "Source-PORT  " + "Destination-PORT  " + "RULE")
    print("{:<8}|{:<16}|{:<16}|{:<16}|{:<16}|{:<16}|{:<8}|".format("Row-ID", "Source-IP", "Destination-IP", "Protocol-IP", "Source-PORT", "Destination-PORT", "RULE"))
    print("{:<8}|{:<16}|{:<16}|{:<16}|{:<16}|{:<16}|{:<8}|".format("--------", "----------------", "----------------", "----------------", "----------------", "----------------", "--------"))

    for record in records:
        # print(str(record[0]) + "\t" + str(record[1]) + "\t" + str(record[2]) + "\t" + str(record[3]) + "\t" + str(record[4]) + "\t" + str(record[5]) + "\t" + str(record[6]))
        print("{:<8}|{:<16}|{:<16}|{:<16}|{:<16}|{:<16}|{:<8}|".format(record[0], record[1], record[2], record[3], record[4], record[5], record[6]))

    conn.commit()
    conn.close()


def display_column():
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("PRAGMA table_info(ip_table)")
    columns = c.fetchall()

    for column in columns:
        print(str(column[1]), end = " " )

    print("")

    conn.commit()
    conn.close()


def check_against(ipsrc, ipdst, ipprt, srcp, dstp):

    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("SELECT rule FROM ip_table WHERE ipsrc = (?) AND ipdst = (?) AND ipprt = (?) AND srcp = (?) AND dstp = (?)", ("n", "n", "n", "n", "n",))
    default_rule = c.fetchone()[0]

    conn.commit()
    conn.close()
    
    # ipsrc, ipdst, ipprt, srcp, dstp = "0", "0", "0", "0", "0"
    # ipsrc, ipdst, ipprt, srcp, dstp = 0, 0, 0, 0, 0
    ipsrc, ipdst, ipprt, srcp, dstp = str(ipsrc), str(ipdst), str(ipprt), str(srcp), str(dstp)

    packet = [ipsrc, ipdst, ipprt, srcp, dstp]
    # print(packet)
    check = []

    i, n, k , count, final_rule = 0, 2, 5, 0, ""

    permutations_with_replacement = itertools.product(range(n), repeat=k)
    for permutation in permutations_with_replacement:
        
        # print(permutation)

        for value in packet:
            
            replacement = permutation[i]
            if  replacement == 1:
                value = "n"

            check.append(value)
            i = i + 1

        check_tup = tuple(check)
        # print(check_tup)

        if check_tup != ('n', 'n', 'n', 'n', 'n'):
            conn = sqlite3.connect('iptables.db')
            c = conn.cursor()

            c.execute("SELECT COUNT(*) FROM ip_table WHERE ipsrc = (?) AND ipdst = (?) AND ipprt = (?) AND srcp = (?) AND dstp = (?)", (check_tup[0], check_tup[1], check_tup[2], check_tup[3], check_tup[4],))
            count = c.fetchone()[0]
            # print(count)

            conn.commit()
            conn.close()

            if count == 1:
        
                conn = sqlite3.connect('iptables.db')
                c = conn.cursor()

                c.execute("SELECT rule FROM ip_table WHERE ipsrc = (?) AND ipdst = (?) AND ipprt = (?) AND srcp = (?) AND dstp = (?)", (check_tup[0], check_tup[1], check_tup[2], check_tup[3], check_tup[4],))
                new_rule = c.fetchone()[0]
                # print(default_rule)
                # print(new_rule)
                # print(final_rule)

                conn.commit()
                conn.close()

                if final_rule == "":
                    final_rule = new_rule

                if final_rule != new_rule:
                    final_rule = default_rule
                
        check = []
        i=0

    if final_rule == "":
        final_rule = default_rule

    return final_rule



if __name__ == "__main__":

    table = "no_display"
    sub_text = 0

    if len(sys.argv)>1:
        if sys.argv[1]=="permit" or sys.argv[1]=="deny":
            rule = sys.argv[1]
            if len(sys.argv)>2 and sys.argv[2] == "all":

                ipsrc, ipdst, ipprt, srcp, dstp = "n", "n", "n", "n", "n"

                rowid = check_table(ipsrc, ipdst, ipprt, srcp, dstp)
                update_record(rowid, rule)

            elif len(sys.argv)>3:
                try:
                    ipsrc = sys.argv[2]
                    ipdst = sys.argv[3]
                    ipprt = sys.argv[4]
                    srcp = sys.argv[5]
                    dstp = sys.argv[6]

                    rowid = check_table(ipsrc, ipdst, ipprt, srcp, dstp)
                    if rowid == "noid":
                        insert_record(ipsrc, ipdst, ipprt, srcp, dstp, rule)
                    else:
                        update_record(rowid, rule)
                except IndexError:
                    sub_text = 1
            else:
                print("invalid input")
                sub_text = 1

        elif sys.argv[1] == "drop":
            if len(sys.argv)>2 and sys.argv[2] == "all":

                ipsrc, ipdst, ipprt, srcp, dstp = "n", "n", "n", "n", "n"

                rowid = check_table(ipsrc, ipdst, ipprt, srcp, dstp)
                update_record(rowid, rule)

            elif len(sys.argv)>3:
                try:
                    ipsrc = sys.argv[2]
                    ipdst = sys.argv[3]
                    ipprt = sys.argv[4]
                    srcp = sys.argv[5]
                    dstp = sys.argv[6]

                    rowid = check_table(ipsrc, ipdst, ipprt, srcp, dstp)
                    if rowid == "noid":
                        print("record does not exist")
                    else:
                        delete_record(rowid)
                except IndexError:
                    sub_text = 1
            else:
                print("invalid input")
                sub_text = 1
        
        elif sys.argv[1] == "reset":

            ipsrc, ipdst, ipprt, srcp, dstp, rule = "n", "n", "n", "n", "n", "permit"

            drop_table()
            create_table()
            insert_record(ipsrc, ipdst, ipprt, srcp, dstp, rule)

        else:
            print("invalid input")
            sub_text = 1

    while table != "display":
        try:
            # check_against()
            display_table()
            table = "display"

        except sqlite3.OperationalError:

            ipsrc, ipdst, ipprt, srcp, dstp, rule = "n", "n", "n", "n", "n", "permit"

            create_table()
            insert_record(ipsrc, ipdst, ipprt, srcp, dstp, rule)

    if sub_text == 1 :
        print("""
Usage : [action] [src_ip] [dst_ip] [ip_proto] [src_port] [dst_port]
Example 1 : [permit] [all]
Example 2 : [deny] [all]
Example 3 : [deny] [192.168.1.1] [192.168.1.2] [n] [n] [n]
Example 4 : [permit] [n] [n] [icmp] [n] [n]
Example 5 : [deny] [192.168.1.1] [n] [n] [8080] [n]
Example 6 : [permit] [n] [192.168.1.2] [n] [n] [n]
Example 7 : [deny] [n] [n] [udp] [n] [9090]
Example 8 : [permit] [n] [n] [tcp] [n] [n] 
""")

# action : 
#       reset     permit      deny        drop
# default:
#       rule      ipsrc   ipdst   ipprt   srcp    dstp
#       permit    n       n       n       n       n