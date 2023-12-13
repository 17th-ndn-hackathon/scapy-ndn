
from scapy.all import PacketListField
from scapyndn.pkt import NdnTypeField, NdnLenField, NonNegativeIntField, \
                         BaseBlockPacket, NdnBasePacket, Name, TYPES, \
                         bind_content_to_name

NFD_MGMT_TYPES = {
    "FaceId": 105,
    "Cost": 106,
    "NfdFib": 128,
    "NextHopRecord": 129
}

class FaceId(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(NFD_MGMT_TYPES["FaceId"]),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class Cost(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(NFD_MGMT_TYPES["Cost"]),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class NextHopRecord(NdnBasePacket):

    TYPES_TO_CLS = { NFD_MGMT_TYPES["FaceId"] : FaceId, NFD_MGMT_TYPES["Cost"] : Cost }

    fields_desc = [
                    NdnTypeField(NFD_MGMT_TYPES["NextHopRecord"]),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, NextHopRecord.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class NfdFib(NdnBasePacket):

    TYPES_TO_CLS = { TYPES["Name"] : Name, NFD_MGMT_TYPES["NextHopRecord"] : NextHopRecord }

    fields_desc = [
                    NdnTypeField(NFD_MGMT_TYPES["NfdFib"]),
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
