
from scapy.all import PacketListField, StrLenField
from scapyndn.pkt import NdnTypeField, NdnLenField, NonNegativeIntField, \
                         NdnBasePacket, Name, TYPES, \
                         bind_content_cls_to_data_name, bind_component_cls_dict_to_name, NameComponent

NFD_MGMT_TYPES = {
    "FaceId": 105,
    "Cost": 106,
    "NfdFib": 128,
    "NextHopRecord": 129
}

class FaceId(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(NFD_MGMT_TYPES["FaceId"]),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class Cost(NdnBasePacket):

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

CONTROL_CMD_TYPES = {
    "ControlParameters"             : 104, # 0x68
    "FaceId"                        : 105, # 0x69
    "Uri"                           : 114, # 0x72
    "LocalUri"                      : 129, # 0x81
    "Origin"                        : 111, # 0x6f
    "Cost"                          : 106, # 0x6a
    "Flags"                         : 108, # 0x6c
    "Capacity"                      : 131, # 0x83
    "Count"                         : 132, # 0x84
    "BaseCongestionMarkingInterval" : 135, # 0x87
    "DefaultCongestionThreshold"    : 136, # 0x88
    "ControlResponse"               : 101, # 0x65
    "StatusCode"                    : 102, # 0x66
    "StatusText"                    : 103, # 0x67
}

class FaceId(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["FaceId"]),
        NdnLenField(),
        NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
    ]

class Origin(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["Origin"]),
        NdnLenField(),
        NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
    ]

class Uri(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["Uri"]),
        NdnLenField(),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length)
    ]

class Cost(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["Cost"]),
        NdnLenField(),
        NonNegativeIntField("value", b"", length_from=lambda pkt: pkt.length)
    ]

class Flags(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["Flags"]),
        NdnLenField(),
        NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
    ]

class ControlParameters(NdnBasePacket):
    TYPES_TO_CLS = {
        CONTROL_CMD_TYPES["FaceId"] : FaceId,
        CONTROL_CMD_TYPES["Uri"] : Uri,
        CONTROL_CMD_TYPES["Cost"] : Cost,
        CONTROL_CMD_TYPES["Origin"] : Origin,
        CONTROL_CMD_TYPES["Flags"] : Flags,
        TYPES["Name"] : Name,
    }

    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["ControlParameters"]),
        NdnLenField(),
        PacketListField("value", [],
                        next_cls_cb=lambda pkt, lst, cur, remain
                        : pkt.guess_ndn_packets(lst, cur, remain, ControlParameters.TYPES_TO_CLS),
                        length_from=lambda pkt: pkt.length)
    ]

class StatusCode(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["StatusCode"]),
        NdnLenField(),
        NonNegativeIntField("value", 200, length_from=lambda pkt: pkt.length)
    ]

class StatusText(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["StatusText"]),
        NdnLenField(),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length)
    ]

class ControlResponse(NdnBasePacket):
    # print(CONTROL_CMD_TYPES["ControlParameters"])
    TYPES_TO_CLS = {
        CONTROL_CMD_TYPES["StatusCode"] : StatusCode,
        CONTROL_CMD_TYPES["StatusText"] : StatusText,
        CONTROL_CMD_TYPES["ControlParameters"]: ControlParameters
    }

    fields_desc = [
                    NdnTypeField(CONTROL_CMD_TYPES["ControlResponse"]),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, ControlResponse.TYPES_TO_CLS),
                                   length_from=lambda pkt: pkt.length)
                  ]

bind_content_cls_to_data_name("/localhost/nfd/fib/list", NfdFib)
bind_content_cls_to_data_name("/localhost/nfd/rib/register", ControlResponse)
bind_component_cls_dict_to_name("/localhost/nfd/rib/register", 0,
                                { CONTROL_CMD_TYPES["ControlParameters"]: ControlParameters} )
