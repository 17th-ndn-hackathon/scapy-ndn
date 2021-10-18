import struct
from datetime import datetime, timedelta

from scapy.all import Field, Packet, ByteField, XByteField, StrField, StrLenField, \
                      PacketListField, conf, StrFixedLenField, \
                      PacketField, XIntField, bind_layers, ConditionalField, \
                      RawVal, Raw, IP, Ether, UDP

from scapy.base_classes import BasePacket, Gen, SetGen

CONVENTIONS = { "MARKER": 1, "TYPED": 2, "EITHER": 3 }

ENCODING_CONVENTION = CONVENTIONS["MARKER"]
DECODING_CONVENTION = CONVENTIONS["EITHER"]

MARKERS = {
            "SEGMENT_MARKER"         : 0x00,
            "SEGMENT_OFFSET_MARKER"  : 0xFB,
            "VERSION_MARKER"         : 0xFD,
            "TIMESTAMP_MARKER"       : 0xFC,
            "SEQUENCE_NUMBER_MARKER" : 0xFE,
          }

MARKER_TYPES = {
                 "seg"          : MARKERS["SEGMENT_MARKER"],
                 "off"          : MARKERS["SEGMENT_OFFSET_MARKER"],
                 "v"            : MARKERS["VERSION_MARKER"],
                 "t"            : MARKERS["TIMESTAMP_MARKER"],
                 "seq"          : MARKERS["SEQUENCE_NUMBER_MARKER"],
               }

TYPES = {
          "ImplicitSha256DigestComponent"  : 1,
          "ParametersSha256DigestComponent": 2,
          "Interest"                       : 5,
          "Data"                           : 6,
          "Name"                           : 7,
          "GenericNameComponent"           : 8,
          "CanBePrefix"                    : 33, # 0x21
          "MustBeFresh"                    : 18, # 0x12
          "ForwardingHint"                 : 30, # 0x1E
          "Nonce"                          : 10, # 0x0A
          "InterestLifetime"               : 12, # 0x0C
          "MetaInfo"                       : 20, # 0x14
          "Content"                        : 21, # 0x15
          "SignatureInfo"                  : 22, # 0x16
          "SignatureValue"                 : 23, # 0x17
          "ContentType"                    : 24, # 0x18
          "FreshnessPeriod"                : 25, # 0x19
          "FinalBlockId"                   : 26, # 0x1A
          "SignatureType"                  : 27, # 0x1B
          "KeyLocator"                     : 28, # 0x1C
          "KeyDigest"                      : 29, # 0x1D
        }

TYPED_NAME_COMP = {
          "SegmentNameComponent"    : 33, # 0x21
          "ByteOffsetNameComponent" : 34, # 0x22
          "VersionNameComponent"    : 35, # 0x23
          "TimestampNameComponent"  : 36, # 0x24
          "SequenceNumNameComponent": 37, # 0x25
        }

NUM_TO_TYPES = {v: k for k, v in TYPES.items()}

TYPE_NUM_TO_CLASS = {}

for k, v in TYPES.items():
    if k not in TYPED_NAME_COMP:
        NUM_TO_TYPES[k] = v

COMP_TYPES = {
          "sha256digest" : TYPES["ImplicitSha256DigestComponent"],
          "params-sha256": TYPES["ParametersSha256DigestComponent"],
          "seg"          : TYPED_NAME_COMP["SegmentNameComponent"],
          "off"          : TYPED_NAME_COMP["ByteOffsetNameComponent"],
          "v"            : TYPED_NAME_COMP["VersionNameComponent"],
          "t"            : TYPED_NAME_COMP["TimestampNameComponent"],
          "seq"          : TYPED_NAME_COMP["SequenceNumNameComponent"],
        }

class NdnLenField(Field):

    def __init__(self, default=None, name="length", fmt="!H"):  # noqa: E501
        Field.__init__(self, name, default, fmt)

    def i2m(self, pkt, x):
        if not pkt:
            return x

        if x is None:
            for field in pkt.fields_desc:
                if field.name != "type" and field.name != "length":
                    fld, fval = pkt.getfield_and_val(field.name)
                    #print("fval: ", fval)
                    if fval is None:
                        continue
                    if x is None:
                        x = fld.i2len(pkt, fval)
                    else:
                        x += fld.i2len(pkt, fval)
        return x

    def addfield(self, pkt, s, val):
        x = self.i2m(pkt, val)
        if not x:
            return s

        if x < 253:
            return s + struct.pack(">B", x)
        elif x < 65536:
            return s + b"\xFD" + struct.pack(">H", x)
        elif x < 4294967296:
            return s + b"\xFE" + struct.pack(">L", x)
        else:
            return s + b"\xFF" + struct.pack(">Q", x)

    def getfield(self, pkt, s):
        # Type deduction failed, so probably unrecognized packet
        if pkt and pkt.getfield_and_val("type")[-1] is None:
            return s, None

        if not s:
            return None, None

        # Check the first octet
        x = ord(s[:self.sz - 1])
        if x < 253:
            return s[1:], self.m2i(pkt, struct.unpack(">B", s[:1])[0])
        elif x == 253:
            return s[3:], self.m2i(pkt, struct.unpack(">H", s[1:3])[0])
        elif x == 254:
            return s[5:], self.m2i(pkt, struct.unpack(">L", s[1:5])[0])
        else:
            return s[9:], self.m2i(pkt, struct.unpack(">Q", s[1:9])[0])

class NdnTypeField(Field):
    __slots__ = ["valid_types"]

    def __init__(self, default, name="type", valid_types=None, fmt="!H"):  # noqa: E501
        # If valid_types is None then all types expected, for example in NameComponent packet
        self.valid_types = valid_types
        Field.__init__(self, name, default, fmt)
        #NdnLenField.__init__(self, default, name, default, fmt)

    def m2i(self, pkt, x):
        #print("NdnTypeField m2i: ", x)
        return super(NdnTypeField, self).m2i(pkt, x)

    def i2m(self, pkt, x):
        #print("i2m", x)
        if isinstance(x, str) and x in COMP_TYPES:
            x = COMP_TYPES[x]

        if self.name in TYPES and x:
            return TYPES[self.name]

        if x is None:
            #print("return empty from ndntypefield")
            return b""
        return x

    def i2repr(self, pkt, x):
        if x is None:
            return ""
        return x

    def addfield(self, pkt, s, val):
        x = self.i2m(pkt, val)
        if not x:
            return s

        if x < 253:
            return s + struct.pack(">B", x)
        elif x < 65536:
            return s + b"\xFD" + struct.pack(">H", x)
        elif x < 4294967296:
            return s + b"\xFE" + struct.pack(">L", x)
        else:
            return s + b"\xFF" + struct.pack(">Q", x)

    def getfield(self, pkt, s):
        if not s:
            return None, None

        #print("NdnTypeField getfield s: ", s, type(s))
        # Check the first octet
        x = ord(s[:self.sz - 1])

        if x < 253:
            rest_of_pkt, val = s[1:], self.m2i(pkt, struct.unpack(">B", s[:1])[0])
        elif x == 253:
            rest_of_pkt, val = s[3:], self.m2i(pkt, struct.unpack(">H", s[1:3])[0])
        elif x == 254:
            rest_of_pkt, val = s[5:], self.m2i(pkt, struct.unpack(">L", s[1:5])[0])
        else:
            rest_of_pkt, val = s[9:], self.m2i(pkt, struct.unpack(">Q", s[1:9])[0])

        if self.valid_types is not None:
            if val not in self.valid_types:
                return s, None

        return rest_of_pkt, val

class NdnZeroLenField(ByteField):
    def __init__(self, name="length"):
        # type: (str, Optional[int]) -> None
        ByteField.__init__(self, name, 0)

class NameComponent(Packet):
    name = "Name Component"

    fields_desc = [
                    NdnTypeField(TYPES['GenericNameComponent']),
                    # Don't need to give it "value" field because NdnLenField computes length
                    # over all the fields except itself and type field above
                    NdnLenField(),
                    # Packet's length field is determined by NdnLenField above and used by value below
                    # Otherwise packet boundaries are not determined correctly and padding will be
                    # merged into the value field
                    # (TODO: How to/Need to do this for Interest field?)
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

    def __init__(self,
                 _pkt=b"",  # type: bytes
                 post_transform=None,  # type: Any
                 _internal=0,  # type: int
                 _underlayer=None,  # type: Optional[Packet]
                 _unescape=False,
                 **fields  # type: Any
                ):

        if "value" in fields:
            if isinstance(fields["value"], str) and _unescape:
                fields["value"] = NameComponent._unescape(fields["value"])
            elif isinstance(fields["value"], int):
                fields["length"], fields["value"] = NameComponent._get_num_len_value(fields["value"])
            elif isinstance(fields["value"], float):
                fields["value"] = NameComponent.from_double(fields["value"])

        Packet.__init__(self, _pkt, post_transform, _internal, _underlayer, **fields)

    def guess_payload_class(self, p):
        return conf.padding_layer

    def show2(self, dump=False, indent=3, lvl="", label_lvl=""):
        return super(NameComponent, self).show2(dump, indent, lvl, label_lvl)

    @staticmethod
    def _from_hex_char(c):
        if c >= ord("0") and c <= ord("9"):
            return c - ord("0")
        elif c >= ord("A") and c <= ord("F"):
            return c - "A" + 10
        elif c >= ord("a") and c <= ord("f"):
            return c - ord("a") + 10
        return -1

    @staticmethod
    def _unescape(input_str):
        unescaped = ""
        i = 0
        while i < len(input_str):
            if input_str[i] == "%" and i + 2 < len(input_str):
                hi = NameComponent._from_hex_char(ord(input_str[i + 1]))
                lo = NameComponent._from_hex_char(ord(input_str[i + 2]))

                if hi < 0 or lo < 0:
                    unescaped += input_str[i] + input_str[i + 1] + input_str[i + 2]
                else:
                    unescaped += chr(hi << 4 | lo)
                i += 2
            else:
                unescaped += input_str[i]
            i += 1
        return unescaped

    @staticmethod
    def from_escaped_string(input_str):
        return NameComponent(value=input_str)

    @staticmethod
    def _get_num_len_value(x):
        if x < 0 or not isinstance(x, int):
            x = 0

        if x <= 255:
            return 1, struct.pack(">B", x)
        elif x < 65535:
            return 2, struct.pack(">H", x)
        elif x < 4294967295:
            return 4, struct.pack(">L", x)
        else:
            return 8, struct.pack(">Q", x)

    @staticmethod
    def from_number(x, comp_type=TYPES['GenericNameComponent']):
        return NameComponent(type=comp_type, value=x)

    def to_number(self):
        fld, val = self.getfield_and_val("value")
        if self.length == 1:
            return struct.unpack(">B", val)[0]
        elif self.length == 2:
            return struct.unpack(">H", val)[0]
        elif self.length == 4:
            return struct.unpack(">L", val)[0]
        elif self.length == 8:
            return struct.unpack(">Q", val)[0]
        else:
            return -1

    @staticmethod
    def from_double(x):
        return struct.pack(">d", x)

    def to_double(self):
        fld, val = self.getfield_and_val("value")
        return struct.unpack(">d", val)[0]

    @staticmethod
    def from_number_with_marker(marker, number):
        l, v = NameComponent._get_num_len_value(number)
        v = struct.pack(">B", marker) + v
        return NameComponent(length=l + 1, value=v)

    @staticmethod
    def from_version(x):
        return NameComponent(type="v", value=x)

    def to_version(self):
        return self.to_number()

    @staticmethod
    def from_timestamp(timepoint):
        microseconds = int((timepoint - datetime(1970, 1, 1)).total_seconds() * 1000000)
        return NameComponent(type="t", value=microseconds)

    def to_timestamp(self):
        return datetime(1970, 1, 1) + timedelta(microseconds=self.to_number())

    @staticmethod
    def from_sequence_number():
        pass

    @staticmethod
    def from_implicit_sha256_digest():
        pass

    @staticmethod
    def from_parameters_sha256_digest():
        pass

class Block(NameComponent):
    name = "Block"

# Following two classes given for convenience with length field set to 32:
class Sha256Digest(NameComponent):
    name = "ImplicitSha256DigestComponent"

    fields_desc = [
                    NdnTypeField(TYPES['ImplicitSha256DigestComponent']),
                    NdnLenField(default=32),
                    StrFixedLenField("value", "", 32)
                  ]

class ParamsSha256(NameComponent):
    name = "ParametersSha256DigestComponent"

    fields_desc = [
                    NdnTypeField(TYPES['ParametersSha256DigestComponent']),
                    NdnLenField(default=32),
                    StrFixedLenField("value", "", 32)
                  ]

class BaseBlockPacket(Packet):
    def guess_payload_class(self, p):
        return conf.padding_layer

class Name(BaseBlockPacket):
    name = "Name"

    fields_desc = [
                    NdnTypeField(TYPES['Name']),
                    NdnLenField(),
                    # Check only for valid NameComponents when reading?
                    PacketListField("value", NameComponent(), NameComponent,
                                    length_from=lambda pkt : pkt.length)
                  ]

#class Nonce(Packet):
class Nonce(BaseBlockPacket):
    name = "Nonce"

    fields_desc = [
                    NdnTypeField(TYPES['Nonce'], valid_types=[TYPES['Nonce']]),
                    NdnLenField(default=4),
                    XIntField("value", 2)
                  ]

class InterestLifetime(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES['InterestLifetime']),
                    NdnLenField(),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class ForwardingHint(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES['ForwardingHint']),
                    NdnLenField(),
                    StrFixedLenField("value", "")
                  ]

class CanBePrefix(BaseBlockPacket):

    fields_desc = [ NdnTypeField(TYPES['CanBePrefix']), NdnZeroLenField() ]

class MustBeFresh(BaseBlockPacket):

    fields_desc = [ NdnTypeField(TYPES['MustBeFresh']), NdnZeroLenField() ]

class TypeBlock(BaseBlockPacket):

    fields_desc = [ NdnTypeField("", "type") ]

class NdnBasePacket(Packet):

    def guess_ndn_packets(self, lst, cur, remain, types_to_cls):
        blk = TypeBlock(remain)
        if blk.type in types_to_cls:
            return types_to_cls[blk.type]
        return Raw

    def guess_payload_class(self, p):
        return conf.padding_layer


class Interest(NdnBasePacket):
    name = "Interest"

    TYPES_TO_CLS = {
                     TYPES["Name"] : Name, TYPES["CanBePrefix"] : CanBePrefix,
                     TYPES["MustBeFresh"] : MustBeFresh,
                     TYPES["ForwardingHint"] : ForwardingHint,
                     TYPES["Nonce"] : Nonce,
                     TYPES["InterestLifetime"] : InterestLifetime,
                     #TYPES["HopLimit"] : HopLimit
                   }

    fields_desc = [
                    NdnTypeField(TYPES['Interest']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, Interest.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class ContentType(BaseBlockPacket):

    CONTENT_TYPES = { "Blob": 0, "Link": 1, "Key": 2, "Nack": 3,
                      "Manifest": 4, "PrefixAnn": 5, "KiteAck": 6 }

    fields_desc = [
                    NdnTypeField(TYPES['ContentType']),
                    NdnLenField(),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class FreshnessPeriod(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES['FreshnessPeriod']),
                    NdnLenField(),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class FinalBlockId(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES['FinalBlockId']),
                    NdnLenField(),
                    PacketField("value", "", NameComponent)
                  ]

class Content(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES["Content"]),
                    NdnLenField(),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class MetaInfo(NdnBasePacket):

    TYPES_TO_CLS = {
                     TYPES["ContentType"] : ContentType,
                     TYPES["FreshnessPeriod"] : FreshnessPeriod,
                     TYPES["FinalBlockId"] : FinalBlockId
                   }

    fields_desc = [
                    NdnTypeField(TYPES['MetaInfo']),
                    NdnLenField(),
                    #StrLenField("value", "", length_from=lambda pkt: pkt.length)
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, MetaInfo.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class SignatureType(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES['SignatureType']),
                    NdnLenField(),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class KeyDigest(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES['KeyDigest']),
                    NdnLenField(),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class KeyLocator(NdnBasePacket):

    TYPES_TO_CLS = {
                     TYPES["Name"] : Name,
                     TYPES["KeyDigest"] : KeyDigest
                   }

    fields_desc = [
                    NdnTypeField(TYPES['KeyLocator']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, KeyLocator.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class SignatureInfo(NdnBasePacket):

    TYPES_TO_CLS = {
                     TYPES["SignatureType"] : SignatureType,
                     TYPES["KeyLocator"] : KeyLocator
                   }

    fields_desc = [
                    NdnTypeField(TYPES['SignatureInfo']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, SignatureInfo.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class SignatureValue(BaseBlockPacket):

    fields_desc = [
                    NdnTypeField(TYPES['SignatureValue']),
                    NdnLenField(),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class Data(NdnBasePacket):

    TYPES_TO_CLS = {
                     TYPES["Name"] : Name,
                     TYPES["MetaInfo"] : MetaInfo,
                     TYPES["Content"] : Content,
                     TYPES["SignatureInfo"]: SignatureInfo,
                     TYPES["SignatureValue"]: SignatureValue
                   }

    fields_desc = [
                    NdnTypeField(TYPES['Data']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, Data.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class NdnGuessPacket(Packet):

    TYPES_TO_CLS = {
                     TYPES["Interest"] : Interest,
                     TYPES["Data"] : Data
                   }

    # Skip printing NdnPacket as this is just a
    # class with no fields to decide the real packet
    def _show_or_dump(self,
                      dump=False,  # type: bool
                      indent=3,  # type: int
                      lvl="",  # type: str
                      label_lvl="",  # type: str
                      first_call=True  # type: bool
                      ):
        return self.payload._show_or_dump(dump, indent, lvl, label_lvl, first_call)

    def guess_payload_class(self, payload):
        blk = TypeBlock(payload)
        if blk.type in NdnGuessPacket.TYPES_TO_CLS:
            return NdnGuessPacket.TYPES_TO_CLS[blk.type]
        else:
            return Block

# bind_layers(IP, Interest)
bind_layers(Ether, NdnGuessPacket, type=0x8624)
bind_layers(UDP, NdnGuessPacket, sport=6363)
