#! /usr/bin/python3

import sqlite3

def show_all():
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("SELECT rowid, * FROM ip_table")
    rules = c.fetchall()

    for rule in rules:
        print(rule[0] + " " + rule[1] + " " + rule[2])

    conn.commit()
    conn.close()



def add_one(ip, port, traffic):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("INSERT INTO ip_table VALUES (?,?,?)", (ip, port, traffic))
    # ip -> string
    # port -> string
    # traffic -> string
    
    conn.commit()
    conn.close()



def add_many(rules):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.executemany("INSERT INTO ip_table VALUES (?,?,?)", rules)
    # rules -> list
    
    conn.commit()
    conn.close()



def delete_one(rid):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("DELETE FROM ip_table WHERE rowid = (?)", rid) 
    # rowid -> int
    # rid -> string

    conn.commit()
    conn.close()



def lookup(port):
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("SELECT rowid, * FROM ip_table WHERE port = (?)", (port,))
    rules = c.fetchall()
    # port -> string

    for rule in rules:
        print(rule[0] + " " + rule[1] + " " + rule[2])

    conn.commit()
    conn.close()



def create():
    conn = sqlite3.connect('iptables.db')
    c = conn.cursor()

    c.execute("""CREATE TABLE ip_table{
                ip NAME
                port NAME
                traffic NAME
    }""")
    
    conn.commit()
    conn.close()
