#! /usr/bin/python3

import sqlite3

#connect
conn = sqlite3.connect('iptables.db')

#cursor
c = conn.cursor()

#CREATE
c.execute("""CREATE TABLE ip_table{
                ip NAME
                port NAME
                traffic NAME
}""")

#VALUES
rules=[
    ('192.168.1.68','8080','in'),
    ('192.168.1.68','9090','out'),
    ('192.168.1.88','9090','in'),
    ('192.168.1.88','8080','out'),
]

#INSERT
c.execute("INSERT INTO ip_table VALUES (?,?,?)", rules)

#SELECT
c.execute("SELECT * FROM ip_table")
c.execute("SELECT * FROM ip_table WHERE port = '9090'")
c.execute("SELECT * FROM ip_table WHERE ip LIKE '%68'")

#UPDATE
c.execute("""UPDATE ip_table SET traffic = 'out'
            WHERE ip LIKE '%68' AND port = '8080'
""")

#DELETE
c.execute("DELETE FROM ip_table WHERE rowid = 4")

#DROP
c.execute("DROP TABLE ip_table")

#query
c.execute("SELECT rowid, * FROM ip_table")
c.execute("SELECT rowid, * FROM ip_table ORDER BY ip DESC")
c.execute("SELECT rowid, * FROM ip_table LIMIT 2")
c.execute("SELECT rowid, * FROM ip_table ORDER BY ip DESC LIMIT 2")

#print
print(c.fetchone()[0])
print(c.fetchmany(2))
print(c.fetchall())

rules = c.fetchall()

for rule in rules:
    print(rule[0] + " " + rule[1] + " " + rule[2])


#commit
conn.commit()

#close
conn.close()