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

    def __init__(self, unix_socket_file="/var/run/nfd.sock"):
        self.outs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.ins = self.outs
        self.outs.connect(unix_socket_file)

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        return NdnGuessPacket, self.ins.recv(x), None

class FaceId(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(105),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class Cost(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(106),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class NextHopRecord(NdnBasePacket):

    TYPES_TO_CLS = { 105 : FaceId, 106 : Cost }

    fields_desc = [
                    NdnTypeField(129),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, NextHopRecord.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class NfdFib(NdnBasePacket):

    TYPES_TO_CLS = { TYPES["Name"] : Name, 129 : NextHopRecord }

    fields_desc = [
                    NdnTypeField(128),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, NfdFib.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

Data.NAMES_TO_CONTENT_CLS["/localhost/nfd/fib/list"] = NfdFib

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

#d['Content'].show2()
#d['SignatureValue'].show2()
