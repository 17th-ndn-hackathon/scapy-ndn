#!/usr/bin/python

import sqlite3
import os

from scapy.all import *
from scapyndn.pkt import *

home_dir = os.getenv("HOME")

con = sqlite3.connect("{}/.ndn/pib.db".format(home_dir))
cur = con.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(cur.fetchall())

#for row in cur.execute("SELECT * FROM identities"):
#    print(row)
#names = [description[0] for description in cur.description]
#print(names)

#for row in cur.execute("SELECT * FROM keys"):
#    print(row)
#names = [description[0] for description in cur.description]
#print(names)

cur = con.execute("SELECT * FROM certificates")
for row in cur:
    print(type(row[2]))
    #key_id   = row[1]
    cert_name = row[2]
    cert_data = row[3]

col_names = [description[0] for description in cur.description]
print(col_names)

print(cert_name)
n = Name(cert_name)
n.show2()

c = Certificate(cert_data)
c.show2()
#hexdump(c)
#print(raw(c))
