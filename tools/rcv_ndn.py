from scapy.all import *
from ndn import *

import argparse

# Config.SHORT_PRINT = True

parser = argparse.ArgumentParser(prog="Listen ")
parser.add_argument("pcapFile", help="Pcap file")
parser.add_argument("-i", type=str, help="Interface")

args = parser.parse_args()

