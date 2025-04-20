# -*- mode: python -*-

from scapy.fields import StrLenField
from scapyndn.pkt import (
    _NdnPacketList_metaclass,
    NdnTypeField,
    NdnLenField,
    NdnBasePacket,
    Name,
    TYPES,
    bind_content_cls_to_data_name,
    bind_content_cls_dict_to_data_name,
    bind_component_cls_dict_to_name,
    TimestampIntField,
    NonNegativeIntBase
)

NFD_GENERAL_DATASETS_CLS_TO_TYPE = {
    "NfdVersion": 128,
    "StartTimestamp": 129,
    "CurrentTimestamp": 130,
    "NNameTreeEntries": 131,
    "NFibEntries": 132,
    "NPitEntries": 133,
    "NMeasurementsEntries": 134,
    "NCsEntries": 135,
    "NInInterests": 144,
    "NInData": 145,
    "NInNacks": 151,
    "NOutInterests": 146,
    "NOutData": 147,
    "NOutNacks": 152,
    "NSatisfiedInterests": 153,
    "NUnsatisfiedInterests": 154
}


class NfdVersion(NdnBasePacket):

    fields_desc = [
        NdnTypeField(NFD_GENERAL_DATASETS_CLS_TO_TYPE["NfdVersion"]),
        NdnLenField(),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length)
    ]


class StartTimestamp(NdnBasePacket):

    fields_desc = [
        NdnTypeField(NFD_GENERAL_DATASETS_CLS_TO_TYPE["StartTimestamp"]),
        NdnLenField(),
        TimestampIntField("value", 0, length_from=lambda pkt: pkt.length)
    ]


class CurrentTimestamp(NdnBasePacket):

    fields_desc = [
        NdnTypeField(NFD_GENERAL_DATASETS_CLS_TO_TYPE["CurrentTimestamp"]),
        NdnLenField(),
        TimestampIntField("value", 0, length_from=lambda pkt: pkt.length)
    ]


class NNameTreeEntries(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NNameTreeEntries"]


class NFibEntries(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NFibEntries"]


class NPitEntries(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NPitEntries"]


class NMeasurementsEntries(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NMeasurementsEntries"]


class NCsEntries(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NCsEntries"]


class NInInterests(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInInterests"]


class NInData(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInData"]


class NInNacks(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInNacks"]


class NOutInterests(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutInterests"]


class NOutData(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutData"]


class NOutNacks(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutNacks"]


class NSatisfiedInterests(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NSatisfiedInterests"]


class NUnsatisfiedInterests(NonNegativeIntBase):
    NdnType = NFD_GENERAL_DATASETS_CLS_TO_TYPE["NUnsatisfiedInterests"]


bind_content_cls_dict_to_data_name("/localhost/nfd/status/general", {
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NfdVersion"]: NfdVersion,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["StartTimestamp"]: StartTimestamp,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["CurrentTimestamp"]: CurrentTimestamp,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NNameTreeEntries"]: NNameTreeEntries,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NFibEntries"]: NFibEntries,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NPitEntries"]: NPitEntries,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NMeasurementsEntries"]:
        NMeasurementsEntries,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NCsEntries"]: NCsEntries,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInInterests"]: NInInterests,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInData"]: NInData,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInNacks"]: NInNacks,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutInterests"]: NOutInterests,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutData"]: NOutData,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutNacks"]: NOutNacks,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NSatisfiedInterests"]:
        NSatisfiedInterests,
    NFD_GENERAL_DATASETS_CLS_TO_TYPE["NUnsatisfiedInterests"]:
        NUnsatisfiedInterests,
})


CONTROL_CMD_TYPES = {
    "ControlParameters": 104,              # 0x68
    "FaceId": 105,                         # 0x69
    "Uri": 114,                            # 0x72
    "LocalUri": 129,                       # 0x81
    "Origin": 111,                         # 0x6f
    "Cost": 106,                           # 0x6a
    "Flags": 108,                          # 0x6c
    "Capacity": 131,                       # 0x83
    "Count": 132,                          # 0x84
    "BaseCongestionMarkingInterval": 135,  # 0x87
    "DefaultCongestionThreshold": 136,     # 0x88
    "ControlResponse": 101,                # 0x65
    "StatusCode": 102,                     # 0x66
    "StatusText": 103,                     # 0x67
    "Strategy": 107                        # 0x6b
}


NFD_CHANNEL_DATASET_CLS_TO_TYPE = {
    "ChannelStatus": 130
}


class LocalUri(NdnBasePacket):

    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["LocalUri"]),
        NdnLenField(),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length)
    ]


class ChannelStatus(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = NFD_CHANNEL_DATASET_CLS_TO_TYPE["ChannelStatus"]
    TypesToCls = {CONTROL_CMD_TYPES["LocalUri"]: LocalUri}


bind_content_cls_dict_to_data_name("/localhost/nfd/faces/channels", {
   NFD_CHANNEL_DATASET_CLS_TO_TYPE["ChannelStatus"]: ChannelStatus
})


NFD_MGMT_TYPES = {
    "FaceId": 105,
    "Cost": 106,
    "NfdFib": 128,
    "NextHopRecord": 129,
    "ExpirationPeriod": 109
}


class FaceId(NonNegativeIntBase):
    NdnType = NFD_MGMT_TYPES["FaceId"]


class Cost(NonNegativeIntBase):
    NdnType = NFD_MGMT_TYPES["Cost"]


class NextHopRecord(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = NFD_MGMT_TYPES["NextHopRecord"]
    TypeToCls = {
        NFD_MGMT_TYPES["FaceId"]: FaceId,
        NFD_MGMT_TYPES["Cost"]: Cost
    }


class NfdFib(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = NFD_MGMT_TYPES["NfdFib"]
    TypeToCls = {
        TYPES["Name"]: Name,
        NFD_MGMT_TYPES["NextHopRecord"]: NextHopRecord
    }


class Origin(NonNegativeIntBase):
    NdnType = CONTROL_CMD_TYPES["Origin"]


class Uri(NonNegativeIntBase):
    NdnType = CONTROL_CMD_TYPES["Uri"]


class Flags(NonNegativeIntBase):
    NdnType = CONTROL_CMD_TYPES["Flags"]


class Strategy(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = CONTROL_CMD_TYPES["Strategy"]
    PktCls = Name


class ControlParameters(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = CONTROL_CMD_TYPES["ControlParameters"]
    TypeToCls = {
        TYPES["Name"]: Name,
        CONTROL_CMD_TYPES["FaceId"]: FaceId,
        CONTROL_CMD_TYPES["Uri"]: Uri,
        CONTROL_CMD_TYPES["Cost"]: Cost,
        CONTROL_CMD_TYPES["Origin"]: Origin,
        CONTROL_CMD_TYPES["Flags"]: Flags,
        CONTROL_CMD_TYPES["Strategy"]: Strategy
    }


class StatusCode(NonNegativeIntBase):
    NdnType = CONTROL_CMD_TYPES["StatusCode"]


class StatusText(NdnBasePacket):
    fields_desc = [
        NdnTypeField(CONTROL_CMD_TYPES["StatusText"]),
        NdnLenField(),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length)
    ]


class ControlResponse(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = CONTROL_CMD_TYPES["ControlResponse"]
    TypeToCls = {
        CONTROL_CMD_TYPES["StatusCode"]: StatusCode,
        CONTROL_CMD_TYPES["StatusText"]: StatusText,
        CONTROL_CMD_TYPES["ControlParameters"]: ControlParameters
    }


bind_content_cls_to_data_name("/localhost/nfd/fib/list", NfdFib)
bind_content_cls_to_data_name("/localhost/nfd/rib/register", ControlResponse)
bind_content_cls_to_data_name("/localhost/nfd/rib/unregister", ControlResponse)
bind_component_cls_dict_to_name("/localhost/nfd/rib/register", 0,
                                {CONTROL_CMD_TYPES["ControlParameters"]:
                                 ControlParameters})
bind_component_cls_dict_to_name("/localhost/nfd/rib/unregister", 0,
                                {CONTROL_CMD_TYPES["ControlParameters"]:
                                 ControlParameters})


FACE_MGMT_CLS_TO_TYPE = {
  "FaceStatus": 128,
  "FaceScope": 132,
  "FacePersistency": 133,
  "LinkType": 134,
  "BaseCongestionMarkingInterval": 135,
  "DefaultCongestionThreshold": 136,
  "Mtu": 137,
  "NInBytes": 148,
  "NOutBytes": 149,
}


class ExpirationPeriod(NonNegativeIntBase):
    NdnType = NFD_MGMT_TYPES["ExpirationPeriod"]


class FaceScope(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["FaceScope"]


class FacePersistency(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["FacePersistency"]


class LinkType(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["LinkType"]


class BaseCongestionMarkingInterval(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["BaseCongestionMarkingInterval"]


class DefaultCongestionThreshold(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["DefaultCongestionThreshold"]


class Mtu(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["Mtu"]


class NInBytes(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["NInBytes"]


class NOutBytes(NonNegativeIntBase):
    NdnType = FACE_MGMT_CLS_TO_TYPE["NOutBytes"]


class FaceStatus(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = FACE_MGMT_CLS_TO_TYPE["FaceStatus"]
    TypeToCls = {
        NFD_MGMT_TYPES["FaceId"]: FaceId,
        CONTROL_CMD_TYPES["Uri"]: Uri,
        CONTROL_CMD_TYPES["LocalUri"]: LocalUri,
        FACE_MGMT_CLS_TO_TYPE["FaceScope"]: FaceScope,
        FACE_MGMT_CLS_TO_TYPE["FacePersistency"]: FacePersistency,
        FACE_MGMT_CLS_TO_TYPE["LinkType"]: LinkType,
        FACE_MGMT_CLS_TO_TYPE["BaseCongestionMarkingInterval"]:
            BaseCongestionMarkingInterval,
        FACE_MGMT_CLS_TO_TYPE["DefaultCongestionThreshold"]:
            DefaultCongestionThreshold,
        FACE_MGMT_CLS_TO_TYPE["Mtu"]: Mtu,
        NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInInterests"]: NInInterests,
        NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInData"]: NInData,
        NFD_GENERAL_DATASETS_CLS_TO_TYPE["NInNacks"]: NInNacks,
        NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutInterests"]: NOutInterests,
        NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutData"]: NOutData,
        NFD_GENERAL_DATASETS_CLS_TO_TYPE["NOutNacks"]: NOutNacks,
        FACE_MGMT_CLS_TO_TYPE["NInBytes"]: NInBytes,
        FACE_MGMT_CLS_TO_TYPE["NOutBytes"]: NOutBytes,
        CONTROL_CMD_TYPES["Flags"]: Flags
    }


bind_content_cls_dict_to_data_name("/localhost/nfd/faces/list", {
   FACE_MGMT_CLS_TO_TYPE["FaceStatus"]: FaceStatus
})


STRATEGY_MGMT_TYPE_TO_CLS = {
    "StrategyChoice": 128
}


class StrategyChoice(NdnBasePacket,
                     metaclass=_NdnPacketList_metaclass):
    NdnType = STRATEGY_MGMT_TYPE_TO_CLS["StrategyChoice"]
    TypeToCls = {
        TYPES["Name"]: Name,
        CONTROL_CMD_TYPES["Strategy"]: Strategy,
    }


bind_content_cls_dict_to_data_name("/localhost/nfd/strategy-choice/list", {
    STRATEGY_MGMT_TYPE_TO_CLS["StrategyChoice"]: StrategyChoice
})


bind_component_cls_dict_to_name("/localhost/nfd/strategy-choice/set", 0,
                                {CONTROL_CMD_TYPES["ControlParameters"]:
                                 ControlParameters})


bind_component_cls_dict_to_name("/localhost/nfd/strategy-choice/unset", 0,
                                {CONTROL_CMD_TYPES["ControlParameters"]:
                                 ControlParameters})


bind_content_cls_to_data_name("/localhost/nfd/strategy-choice/set",
                              ControlResponse)


bind_content_cls_to_data_name("/localhost/nfd/strategy-choice/unset",
                              ControlResponse)


CS_MGMT_TYPE_TO_CLS = {
    "CsInfo": 128,
    "Capacity": 131,
    "Flags": 108,
    "NHits": 129,
    "NMisses": 130
}


class Capacity(NonNegativeIntBase):
    NdnType = CS_MGMT_TYPE_TO_CLS["Capacity"]


class NHits(NonNegativeIntBase):
    NdnType = CS_MGMT_TYPE_TO_CLS["Capacity"]


class NMisses(NonNegativeIntBase):
    NdnType = CS_MGMT_TYPE_TO_CLS["Capacity"]


class CsInfo(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = CS_MGMT_TYPE_TO_CLS["CsInfo"]
    TypeToCls = {
        CS_MGMT_TYPE_TO_CLS["Capacity"]: Capacity,
        CS_MGMT_TYPE_TO_CLS["Flags"]: Flags,
        NFD_GENERAL_DATASETS_CLS_TO_TYPE["NCsEntries"]: NCsEntries,
        CS_MGMT_TYPE_TO_CLS["NHits"]: NHits,
        CS_MGMT_TYPE_TO_CLS["NMisses"]: NMisses
    }


bind_content_cls_dict_to_data_name("/localhost/nfd/cs/info", {
    CS_MGMT_TYPE_TO_CLS["CsInfo"]: CsInfo
})
