
from scapy.all import PacketListField
from scapyndn.pkt import NdnTypeField, NdnLenField, NonNegativeIntField, \
                         BaseBlockPacket, NdnBasePacket, Name, TYPES, \
                         bind_content_to_name

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

#n = Name(value = NameComponent(value="localhost") / \
#                 NameComponent(value="nfd") / \
#                 NameComponent(value="fib") / \
#                 NameComponent(value="list"))

bind_content_to_name("/localhost/nfd/fib/list", NfdFib)
