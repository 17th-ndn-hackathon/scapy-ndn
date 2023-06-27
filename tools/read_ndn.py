from scapy.all import *
from ndn import *

import argparse

# Config.SHORT_PRINT = True

parser = argparse.ArgumentParser(prog="Read NDN")
parser.add_argument("pcapFile", help="Pcap file")
parser.add_argument("-n", type=int, default=0, help="Packet number")

args = parser.parse_args()

#p = rdpcap("../ndn-tools/tests/dissect-wireshark/nameuri.pcap")
p = rdpcap(args.pcapFile)
#for i in range(len(p)):
#    p[i].show2()
#    hexdump(p[i])
p[args.n].show2()
hexdump(p[args.n])
