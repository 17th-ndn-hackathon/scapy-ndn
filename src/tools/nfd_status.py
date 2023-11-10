import socket
import time
import sys

from scapy.all import *
from scapyndn.pkt import *
from scapyndn.contents.nfd import *

# Depending on what you want to do , you may be able to use the SimpleSocket
# and StreamSocket, instantiated with unix socket as a parameter. Then
# you will be able to read and write packets in them.
# But you may need to write a whole SuperSocket subclass.

class UnixSocket(SuperSocket):
    desc = "Unix sockets using Raw sockets (PF_INET/SOCK_RAW)"

    def __init__(self, unix_socket_file="/var/run/nfd.sock"):
        self.outs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.ins = self.outs
        self.outs.connect(unix_socket_file)

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        return NdnGuessPacket, self.ins.recv(x), None

us = UnixSocket()

n = Name(value = NameComponent(value="localhost") / \
                 NameComponent(value="nfd") / \
                 NameComponent(value="fib") / \
                 NameComponent(value="list"))

i = Interest(value = n / CanBePrefix() / MustBeFresh())

t = AsyncSniffer(opened_socket=us, prn=lambda x: hexdump(x))
t.start()
sendp(i, socket = us)
time.sleep(0.1)
t.stop()
d = t.results[0]
#print(type(d))
d.show2()
print(raw(d))

#for idx, i in enumerate(d.value):
#    i.canvas_dump().writePDFfile('test-{}.pdf'.format(idx))

#d.canvas_dump().writePDFfile('test1.pdf') #, rebuild=0)

#d['Content'].show2()
#d['SignatureValue'].show2()
