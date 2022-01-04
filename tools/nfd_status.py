import socket
import time
import sys

#print(sys.path)

sys.path.append("/home/ashlesh/ndn-src/scapy-ndn")

#sys.exit(1)

from scapy.all import *
from ndn import *

# Depending on what you want to do , you may be able to use the SimpleSocket
# and StreamSocket, instantiated with you unix socket as a parameter. Then
# you will be able to read and write packets in them.
# But you may need to write a whole SuperSocket subclass.

class UnixSocket(SuperSocket):
    desc = "Unix sockets using Raw sockets (PF_INET/SOCK_RAW)"

    def __init__(self):
        self.outs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.ins = self.outs
        self.outs.connect("/var/run/nfd.sock")

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
i.show2()

t = AsyncSniffer(opened_socket=us, prn=lambda x: x.show2())
t.start()
sendp(i, socket = us)
time.sleep(0.1)
t.stop()
#print(type(t.results[0]))
