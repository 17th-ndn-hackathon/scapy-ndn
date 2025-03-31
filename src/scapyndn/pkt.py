# -*- mode: python -*-
import struct
from datetime import datetime, timedelta

from scapy.all import Field, Packet, ByteField, XByteField, StrField, StrLenField, \
                      PacketListField, conf, StrFixedLenField, \
                      PacketField, PacketLenField, XIntField, bind_layers, ConditionalField, \
                      RawVal, Raw, Ether, UDP, TCP, ECDSASignature, raw, IEEEDoubleField, \
                      Packet_metaclass

from scapy.layers.x509 import X509_SubjectPublicKeyInfo
from scapy.utils import binrepr
from scapy.compat import orb

from scapy.base_classes import BasePacket, Gen, SetGen

CONVENTIONS = { "MARKER": 1, "TYPED": 2, "EITHER": 3 }

ENCODING_CONVENTION = CONVENTIONS["MARKER"]
DECODING_CONVENTION = CONVENTIONS["EITHER"]

MARKERS = {
            "SEGMENT_MARKER"         : 0x00,
            "SEGMENT_OFFSET_MARKER"  : 0xFB, # 251
            "TIMESTAMP_MARKER"       : 0xFC, # 252
            "VERSION_MARKER"         : 0xFD, # 253
            "SEQUENCE_NUMBER_MARKER" : 0xFE, # 254
          }

MARKER_TYPES = {
                 "seg"          : MARKERS["SEGMENT_MARKER"],
                 "off"          : MARKERS["SEGMENT_OFFSET_MARKER"],
                 "v"            : MARKERS["VERSION_MARKER"],
                 "t"            : MARKERS["TIMESTAMP_MARKER"],
                 "seq"          : MARKERS["SEQUENCE_NUMBER_MARKER"],
               }

TYPES = {
          "Interest"                       : 5,
          "Data"                           : 6,

          "Name"                           : 7,
          "GenericNameComponent"           : 8,
          "ImplicitSha256DigestComponent"  : 1,
          "ParametersSha256DigestComponent": 2,
          "SegmentNameComponent"           : 50, # 0x32
          "ByteOffsetNameComponent"        : 52, # 0x34
          "VersionNameComponent"           : 54, # 0x36
          "TimestampNameComponent"         : 56, # 0x38
          "SequenceNumNameComponent"       : 58, # 0x3A

          "CanBePrefix"                    : 33, # 0x21
          "MustBeFresh"                    : 18, # 0x12
          "ForwardingHint"                 : 30, # 0x1E
          "Nonce"                          : 10, # 0x0A
          "InterestLifetime"               : 12, # 0x0C
          "HopLimit"                       : 34, # 0x22
          "ApplicationParameters"          : 36, # 0x24
          "InterestSignatureInfo"          : 44, # 0x2C
          "InterestSignatureValue"         : 46, # 0x2E
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
          "SignatureNonce"                 : 38, # 0x26
          "SignatureTime"                  : 40, # 0x28
          "SignatureSeqNum"                : 42, # 0x2A
          "ValidityPeriod"                 : 253, # 0xFD
          "NotBefore"                      : 254, # 0xFE
          "NotAfter"                       : 255, # 0xFF
        }

NUM_TO_TYPES = {v: k for k, v in TYPES.items()}

COMP_TYPES = {
          "sha256digest" : TYPES["ImplicitSha256DigestComponent"],
          "params-sha256": TYPES["ParametersSha256DigestComponent"],
          "seg"          : TYPES["SegmentNameComponent"],
          "off"          : TYPES["ByteOffsetNameComponent"],
          "v"            : TYPES["VersionNameComponent"],
          "t"            : TYPES["TimestampNameComponent"],
          "seq"          : TYPES["SequenceNumNameComponent"],
        }
NUM_TO_TYPED_STR = {v: k for k, v in COMP_TYPES.items()}

LP_TYPES = {
             "LpPacket"           : 100, # 0x64
             "Fragment"           : 80,  # 0x50
             "Sequence"           : 81,  # 0x51
             "FragIndex"          : 82,  # 0x52
             "FragCount"          : 83,  # 0x53
             "HopCount_ndnSIM"    : 84,  # 0x54
             "GeoTag_ndnSIM"      : 85,  # 0x55
             "PitToken"           : 98,  # 0x62
             "Nack"               : 800, # 0x320
             "NackReason"         : 801, # 0x321
             "IncomingFaceId"     : 812, # 0x32C
             "NextHopFaceId"      : 816, # 0x330
             "CachePolicy"        : 820, # 0x334
             "CachePolicyType"    : 821, # 0x335
             "CachePolicyMark"    : 832, # 0x340
             "Ack"                : 836, # 0x344
             "TxSequence"         : 840, # 0x348
             "NonDiscovery"       : 844, # 0x34C
             "PrefixAnnouncement" : 848, # 0x350
           }

class NdnStrLenField(StrLenField):

    def __init__(self, name, default, length_from):
        super(NdnStrLenField, self).__init__(name, default, length_from)

    def i2m(self, pkt, x):
        # Support for int and float if someone uses value=255 or value=100.2 in NameComponent
        # instead of dedicated class NonNegativeIntField
        if type(x) == int:
            if x <= 255:
                return struct.pack(">B", x)
            elif x < 65536:
                return struct.pack(">H", x)
            elif x < 4294967296:
                return struct.pack(">L", x)
            else:
                return struct.pack(">Q", x)
        if type(x) == float:
            return struct.pack(">d", x)

        return super(NdnStrLenField, self).i2m(pkt, x)

class NonNegativeIntField(Field):
    __slots__ = ["length_from", "enum"]

    def __init__(self, name, default, length_from=None, enum=None):
        Field.__init__(self, name, default)
        self.length_from = length_from
        self.enum = enum

    def i2len(self, pkt, x):
        if not isinstance(x, int) or x < 0:
            x = 0

        if x <= 255:
            l = 1
        elif x < 65535:
            l = 2
        elif x < 4294967295:
            l = 4
        else:
            l = 8
        self.sz = l

        return l

    def addfield(self, pkt, s, val):
        x = self.i2m(pkt, val)
        if not x:
            return s

        if x <= 255:
            return s + struct.pack(">B", x)
        elif x < 65535:
            return s + struct.pack(">H", x)
        elif x < 4294967296:
            return s + struct.pack(">L", x)
        else:
            return s + struct.pack(">Q", x)

    def getfield(self, pkt, s):
        if not s:
            return None, None

        len_pkt = (self.length_from or (lambda x: 0))(pkt)
        self.sz = len_pkt

        val = None
        if self.sz == 1:
            val = self.m2i(pkt, struct.unpack(">B", s[:len_pkt])[0])
        elif self.sz == 2:
            val = self.m2i(pkt, struct.unpack(">H", s[:len_pkt])[0])
        elif self.sz == 4:
            val = self.m2i(pkt, struct.unpack(">L", s[:len_pkt])[0])
        elif self.sz == 8:
            val = self.m2i(pkt, struct.unpack(">Q", s[:len_pkt])[0])

        return s[len_pkt:], val

    def i2repr(self, pkt, x):
        if self.enum and x in self.enum:
            return "{} [{}]".format(x, self.enum[x])
        elif x is not None:
            return "{0} (0x{0:02X})".format(x)
        return ""

class TimestampIntField(NonNegativeIntField):

    def addfield(self, pkt, s, val):
        if isinstance(val, datetime):
            val = int(val.timestamp() * 1000)
        return super(TimestampIntField, self).addfield(pkt, s, val)

    def i2len(self, pkt, x):
        if isinstance(x, datetime):
            x = int(x.timestamp() * 1000)
        return super(TimestampIntField, self).i2len(pkt, x)

    def i2repr(self, pkt, x):
        if x is None:
            return ""

        if isinstance(x, int):
            x_dt = datetime.fromtimestamp(x / 1000)
            return "{} [{}]".format(x, x_dt)

        return x

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
                    # print("fld, fval: ", fld, fval)
                    if fval is None:
                        continue

                    if type(fval) == int:
                        if fval <= 255:
                            fld_len = 1
                        elif fval < 65535:
                            fld_len = 2
                        elif fval < 4294967295:
                            fld_len = 4
                        else:
                            fld_len = 8
                    elif type(fval) == float:
                        fld_len = 8
                    else:
                        fld_len = fld.i2len(pkt, fval)

                    if x is None:
                        # print("i2m: ", fld, fval)
                        x = fld_len
                    else:
                        x += fld_len

        # Zero-length
        if x is None:
            x = 0

        return x

    def addfield(self, pkt, s, val):
        x = self.i2m(pkt, val)

        if x is None:
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
            return s, None

        # Check the first octet
        x = ord(s[:1])
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

    def __init__(self, default, valid_types=None, fmt="!H"):  # noqa: E501
        # If valid_types is None then all types expected, for example in NameComponent packet
        self.valid_types = valid_types
        # Scapy is using "type" in various places so should be safe to do so
        Field.__init__(self, "type", default, fmt)

    def m2i(self, pkt, x):
        #print("NdnTypeField m2i: ", x)
        return super(NdnTypeField, self).m2i(pkt, x)

    def i2m(self, pkt, x):
        #print("i2m", x)
        if isinstance(x, str) and x in COMP_TYPES:
            x = COMP_TYPES[x]

        # if self.name in TYPES and x:
        if self.name in TYPES:
            return TYPES[self.name]
        elif self.name in LP_TYPES:
            return LP_TYPES[self.name]

        if x is None:
            return 0
        return x

    # TODO: Show any known type name in bracket for that particular packet (something like enum)
    # Maybe helpful if multiple type like NameComponent - else it should be clear by Name
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

        #if type(s) == list:
        #    return None, None

        x = ord(s[:1])

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

class Raw_ASN1_BIT_STRING(StrField):
    def i2repr(self,
               pkt,  # type: Optional[Packet]
               v,  # type: bytes
               ):
        # type: (...) -> str

        s = v
        if isinstance(v, bytes):
            v = "".join(binrepr(orb(x)).zfill(8) for x in v)

        if len(s) > 16:
            s = s[:10] + b"..." + s[-10:]
        if len(v) > 20:
            v = v[:10] + "..." + v[-10:]
        return "<%s[%s]=%r>" % (
            "Raw_ASN1_BIT_STRING",
            v,
            s
        )

class TypeBlock(Packet):

    fields_desc = [ NdnTypeField("") ]

class LengthCheckBlock(Packet):

    fields_desc = [
                    NdnTypeField(""),
                    NdnLenField(),
                    NdnStrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

class Block(Packet):
   fields_desc = [
       NdnTypeField(""),
       NdnLenField(),
       PacketListField("value", [],
                       next_cls_cb=lambda pkt, lst, cur, remain :
                           pkt.guess_ndn_packets(lst, cur, remain),
                       length_from=lambda pkt: pkt.length)
   ]

   def guess_ndn_packets(self, lst, cur, remain):
       b = LengthCheckBlock(remain)
       if b.length != len(b.value):
           return Raw
       return Block

   def guess_payload_class(self, p):
       return conf.padding_layer

class NdnBasePacket(Packet):

    # Default can be a TLV Block instead of Raw
    def guess_ndn_packets(self, lst, cur, remain, types_to_cls, default=Block):
        blk = TypeBlock(remain)
        if blk.type in types_to_cls:
            return types_to_cls[blk.type]
        return default

    def guess_payload_class(self, payload):
        return conf.padding_layer

class NameComponent(NdnBasePacket):
    name = "Name Component (String)"

    fields_desc = [
                    NdnTypeField(TYPES['GenericNameComponent']),
                    NdnLenField(),
                    NdnStrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

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
    def escape(byts):
        escaped = ""
        for b in byts:
            if ((b >= ord("a") and b <= ord("z")) or \
                (b >= ord("A") and b <= ord("Z")) or \
                (b >= ord("0") and b <= ord("9")) or \
                b == "-" or b == "." or \
                b == "_" or b == "~"):
                escaped += chr(b)
            else:
                escaped += "%"
                escaped += "{0:02x}".format(b)
        return escaped

    def to_number(self):
        val = self.getfieldval("value")
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

    def to_double(self):
        val = self.getfieldval("value")
        return struct.unpack(">d", val)[0]

    def to_uri(self):
        uri_str = ""
        try:
            val = self.getfieldval("value")
        except ValueError as e:
            return uri_str

        if type(val) == bytes:
            try:
                val = val.decode()
            except Exception as e:
                pass

        if type(val) == bytes:
            uri_str += NameComponent.escape(val)
        elif type(val) == list:
            for i in val:
                uri_str += NameComponent.escape(bytes(i))
        elif type(val) == str:
            uri_str += val
        elif type(val) == int:
            nc_type = self.getfieldval("type")
            if nc_type in NUM_TO_TYPED_STR:
                uri_str += "{}/{}".format(NUM_TO_TYPED_STR[nc_type], val)
            else:
                x = b""
                if val <= 255:
                    x = struct.pack(">B", val)
                elif val < 65536:
                    x = struct.pack(">H", val)
                elif val < 4294967296:
                    x = struct.pack(">L", val)
                else:
                    x = struct.pack(">Q", val)
                uri_str += NameComponent.escape(x)
        elif type(val) == float:
            uri_str += NameComponent.escape(struct.pack(">d", val))
        else:
            uri_str += NameComponent.escape(bytes(val))
        return uri_str

class StrFieldPacket(Packet):

    fields_desc = [ StrField("value", "") ]

# Could also apply/extend this class to other Packets
class _NdnPacketList_metaclass(Packet_metaclass):

    def __new__(cls, name, bases, dct):

        fields_desc = []
        if "NdnType" not in dct:
            # Will throw an error that default is not provided,
            # else we can provide empty string here like TypeBlock
            fields_desc.append(NdnTypeField())
        else:
            fields_desc.append(NdnTypeField(dct["NdnType"]))

        fields_desc.append(NdnLenField())

        if "TypeToCls" in dct:
            fields_desc.append(
                PacketListField("value", [],
                                next_cls_cb=lambda pkt, lst, cur, remain
                                : pkt.guess_ndn_packets(lst, cur, remain,
                                                        dct["TypeToCls"],
                                                        StrFieldPacket),
                                length_from=lambda pkt: pkt.length)
            )
        elif "PktCls" in dct:
            fields_desc.append(
                PacketListField("value", [], dct["PktCls"], length_from=lambda pkt: pkt.length)
            )
        else:
            fields_desc.append(
                PacketListField("value", [], length_from=lambda pkt: pkt.length)
            )

        dct['fields_desc'] = fields_desc

        return super(_NdnPacketList_metaclass, cls).__new__(cls, name, bases, dct)

class _NdnNonNegativeInteger_metaclass(Packet_metaclass):

    def __new__(cls, name, bases, dct):

        fields_desc = []
        if "NdnType" not in dct:
            # Will throw an error that default is not provided,
            # else we can provide empty string here like TypeBlock
            fields_desc.append(NdnTypeField())
        else:
            fields_desc.append(NdnTypeField(dct["NdnType"]))

        fields_desc.append(NdnLenField())
        fields_desc.append(NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length))

        dct['fields_desc'] = fields_desc

        return super(_NdnNonNegativeInteger_metaclass, cls).__new__(cls, name, bases, dct)

class NonNegativeIntBase(NdnBasePacket, metaclass=_NdnNonNegativeInteger_metaclass):
    NdnType = TYPES['GenericNameComponent']

class PktListNameComponent(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = TYPES['GenericNameComponent']
    TypeToCls  = {}

class VersionNameComponent(NameComponent):
    name = "Version Name Component"

    fields_desc = [
                    NdnTypeField(TYPES['VersionNameComponent']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class SegmentNameComponent(NameComponent):
    name = "Segment Name Component"

    fields_desc = [
                    NdnTypeField(TYPES['SegmentNameComponent']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class TimestampNameComponent(NameComponent):

    name = "Timestamp Name Component"

    fields_desc = [
                    NdnTypeField(TYPES['TimestampNameComponent']),
                    NdnLenField(),
                    TimestampIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class NonNegIntNameComponent(NameComponent):
    name = "Non-Negative Integer Name Component"

    fields_desc = [
                    NdnTypeField(TYPES['GenericNameComponent']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class DoubleNameComponent(NameComponent):
    name = "Double Name Component"

    fields_desc = [
                    NdnTypeField(TYPES['GenericNameComponent']),
                    NdnLenField(),
                    IEEEDoubleField("value", 0)
                  ]

# Following two classes given for convenience with length field set to 32:
class ImplicitSha256DigestComponent(NameComponent):
    name = "ImplicitSha256DigestComponent"

    fields_desc = [
                    NdnTypeField(TYPES['ImplicitSha256DigestComponent']),
                    NdnLenField(default=32),
                    StrFixedLenField("value", b"", 32)
                  ]

class ParametersSha256DigestComponent(NameComponent):
    name = "ParametersSha256DigestComponent"

    fields_desc = [
                    NdnTypeField(TYPES['ParametersSha256DigestComponent']),
                    NdnLenField(default=32),
                    StrFixedLenField("value", b"", 32)
                  ]

NAME_URI_TO_NAME_COMPONENT_VALUE_CLS = {}
def bind_cls_to_name(name_uri, num_after_name, cls):
    # type: (str, int, Packet) -> None
    """
    When dissecting Name, it could have a Packet type other than NameComponent*
    such as ControlParameters.
        * name_uri: str such as /localhop/sync/
        * num_after_name: int such as 0 i.e. immediately after the given name_uri
        * cls: cls such as IBF
    """
    if name_uri not in NAME_URI_TO_NAME_COMPONENT_VALUE_CLS:
        NAME_URI_TO_NAME_COMPONENT_VALUE_CLS[name_uri] = { num_after_name : cls }
    else:
        NAME_URI_TO_NAME_COMPONENT_VALUE_CLS[name_uri][num_after_name] = cls

def bind_component_cls_dict_to_name(name_uri, num_after_name, types_to_cls):
    # type: (str, int, dict[int, Packet]) -> None
    """
    When dissecting Name, it could have various Packet types other than NameComponent*
    such as ControlParameters
        * name_uri: str such as /localhost/nfd/rib/register
        * num_after_name: int such as 0 i.e. immediately after the given name_uri
        * types_to_cls: dict such as
          { CONTROL_CMD_TYPES["ControlParameters"]: ControlParameters}
    """
    class GuessPktListNameComponent(NameComponent, metaclass=_NdnPacketList_metaclass):
        NdnType   = TYPES['GenericNameComponent']
        TypeToCls = types_to_cls
    bind_cls_to_name(name_uri, num_after_name, GuessPktListNameComponent)

def bind_component_cls_to_name(name_uri, num_after_name, pkt_cls):
    # type: (str, int, Packet) -> None
    """
    When dissecting Name, it could have a list of given Packet type
    other than NameComponent* such as NonNegIntNameComponent.
        * name_uri: str such as /localhop/test/
        * num_after_name: int such as 0 i.e. immediately after the given name_uri
        * pkt_cls: cls such as NonNegIntNameComponent
    """
    class PktListNameComponent(NameComponent, metaclass=_NdnPacketList_metaclass):
        NdnType = TYPES['GenericNameComponent']
        PktCls  = pkt_cls
    bind_cls_to_name(name_uri, num_after_name, PktListNameComponent)

class Name(NdnBasePacket):
    name = "Name"

    TYPES_TO_CLS = {
        TYPES["GenericNameComponent"] : NameComponent,
        TYPES["ImplicitSha256DigestComponent"] : ImplicitSha256DigestComponent,
        TYPES["ParametersSha256DigestComponent"] : ParametersSha256DigestComponent,
        TYPES['VersionNameComponent']: VersionNameComponent,
        TYPES['SegmentNameComponent']: SegmentNameComponent,
    }

    fields_desc = [
                    NdnTypeField(TYPES['Name']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, Name.TYPES_TO_CLS, NameComponent),
                                     length_from=lambda pkt: pkt.length)
              ]

    def guess_ndn_packets(self, lst, cur, remain, types_to_cls, default=Raw):
        '''
        Override to decode content within names
        '''
        blk = TypeBlock(remain)

        component_list = lst.copy()
        if cur is not None:
            component_list.append(cur)

        name_so_far = "/"
        bound_name = None
        comp_num_after_prefix = 0
        for idx, nc in enumerate(component_list):
            name_so_far += nc.to_uri()
            # print(name_so_far)

            if name_so_far in NAME_URI_TO_NAME_COMPONENT_VALUE_CLS:
                bound_name = name_so_far
            elif bound_name is not None:
                comp_num_after_prefix += 1

            if idx != len(component_list) - 1:
                name_so_far += '/'

        if bound_name is not None:
            if comp_num_after_prefix in NAME_URI_TO_NAME_COMPONENT_VALUE_CLS[bound_name]:
                return NAME_URI_TO_NAME_COMPONENT_VALUE_CLS[bound_name][comp_num_after_prefix]

        # /localhost/nfd/rib/register/<control-parameters>/<sha256-digest>

        if blk.type in types_to_cls:
            return types_to_cls[blk.type]
        return default

    def _to_uri(self):
        name_str = "/"
        for idx, f in enumerate(self.value):
            name_str += f.to_uri()
            if idx != len(self.value) - 1:
                name_str += "/"
        return name_str

    def to_uri(self):
        return self.__class__(raw(self))._to_uri()

    def is_prefix_of(self, other):
        if type(other) == str:
            other_component_list = other[1:].split("/")
            if len(other_component_list) > len(self.value):
                return False, len(other_component_list)

            for idx, other_comp in enumerate(other_component_list):
                if other_comp != self.value[idx].to_uri():
                    return False, len(other_component_list)
            return True, len(other_component_list)
        return False, 0

class Nonce(NdnBasePacket):
    name = "Nonce"

    fields_desc = [
                    NdnTypeField(TYPES['Nonce'], valid_types=[TYPES['Nonce']]),
                    NdnLenField(default=4),
                    XIntField("value", 2)
                  ]

class InterestLifetime(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['InterestLifetime']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class ForwardingHint(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['ForwardingHint']),
                    NdnLenField(),
                    PacketLenField("value", "", Name, length_from=lambda pkt: pkt.length)
                  ]

class CanBePrefix(NdnBasePacket):

    fields_desc = [ NdnTypeField(TYPES['CanBePrefix']), NdnZeroLenField() ]

class MustBeFresh(NdnBasePacket):

    fields_desc = [ NdnTypeField(TYPES['MustBeFresh']), NdnZeroLenField() ]

class HopLimit(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['HopLimit']),
                    NdnLenField(default=1),
                    ByteField("value", 0)
                  ]

class ApplicationParameters(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES["ApplicationParameters"]),
                    NdnLenField(),
                    StrLenField("value", b"", length_from=lambda pkt: pkt.length)
                  ]

class ContentType(NdnBasePacket):

    CONTENT_TYPES = { 0: "Blob", 1: "Link", 2: "Key", 3: "Nack",
                      4: "Manifest", 5: "PrefixAnn", 6: "KiteAck" }

    fields_desc = [
                    NdnTypeField(TYPES['ContentType']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length, enum=CONTENT_TYPES)
                  ]

class FreshnessPeriod(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['FreshnessPeriod']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class FinalBlockId(NdnBasePacket):

    TYPES_TO_CLS = { TYPES["GenericNameComponent"] : NameComponent,
                     TYPES['VersionNameComponent']: VersionNameComponent,
                     TYPES['SegmentNameComponent']: SegmentNameComponent }

    fields_desc = [
                    NdnTypeField(TYPES['FinalBlockId']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, FinalBlockId.TYPES_TO_CLS, NameComponent),
                                     length_from=lambda pkt: pkt.length)
                  ]

class Content(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES["Content"]),
                    NdnLenField(),
                    PacketListField("value", [], Block,
                                    length_from=lambda pkt: pkt.length)
                  ]

class SubjectPublicKeyInfoContent(NdnBasePacket):
    name = "Content"

    fields_desc = [
                    NdnTypeField(TYPES["Content"]),
                    NdnLenField(),
                    PacketListField("value", [], X509_SubjectPublicKeyInfo,
                                    length_from=lambda pkt: pkt.length)
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
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, MetaInfo.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class SignatureType(NdnBasePacket):

    SIG_TYPE_VALUES = { 0 : "DigestSha256", 1 : "SignatureSha256WithRsa",
                        3 : "SignatureSha256WithEcdsa", 4 : "SignatureHmacWithSha256" }

    fields_desc = [
                    NdnTypeField(TYPES['SignatureType']),
                    NdnLenField(),
                    NonNegativeIntField("value", "", length_from=lambda pkt: pkt.length, enum=SIG_TYPE_VALUES)
                  ]

class KeyDigest(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['KeyDigest']),
                    NdnLenField(),
                    StrLenField("value", b"", length_from=lambda pkt: pkt.length)
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

class SignatureNonce(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['SignatureNonce']),
                    NdnLenField(),
                    StrLenField("value", b"", length_from=lambda pkt: pkt.length)
                  ]

class SignatureTime(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['SignatureTime']),
                    NdnLenField(),
                    TimestampIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class SignatureSeqNum(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['SignatureSeqNum']),
                    NdnLenField(default=4),
                    NonNegativeIntField("value", 0)
                  ]

class NotBefore(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['NotBefore']),
                    NdnLenField(),
                    StrLenField("value", b"", length_from=lambda pkt: pkt.length)
                  ]

class NotAfter(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES['NotAfter']),
                    NdnLenField(),
                    StrLenField("value", b"", length_from=lambda pkt: pkt.length)
                  ]

class ValidityPeriod(NdnBasePacket):

    TYPES_TO_CLS = {
                     TYPES["NotBefore"] : NotBefore,
                     TYPES["NotAfter"] : NotAfter
                   }

    fields_desc = [
                    NdnTypeField(TYPES['ValidityPeriod']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, ValidityPeriod.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class SignatureInfo(NdnBasePacket):

    # This should Cover Data, Interest, and Certificate
    TYPES_TO_CLS = {
                     TYPES["SignatureType"] : SignatureType,
                     TYPES["KeyLocator"] : KeyLocator,
                     TYPES["ValidityPeriod"] : ValidityPeriod,
                     TYPES["SignatureNonce"] : SignatureNonce,
                     TYPES["SignatureTime"] : SignatureTime,
                     TYPES["SignatureSeqNum"] : SignatureSeqNum
                   }

    fields_desc = [
                    NdnTypeField(TYPES['SignatureInfo']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, SignatureInfo.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class DigestSha256(Packet):

    fields_desc = [ StrField("value", b"")  ]

class RsaSignature(Packet):

    fields_desc = [ Raw_ASN1_BIT_STRING("value", b"")  ]

class SignatureValue(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = TYPES['SignatureValue']

# Why use PktCls is here as value should not be a PacketList?
# Becasue ECSDASignature is a Packet we should use PacketField
class ECDSASignatureValue(NdnBasePacket): #, metaclass=_NdnPacketList_metaclass):
    #name = "ECDSA PacketListField"
    fields_desc = [
                    NdnTypeField(TYPES['SignatureValue']),
                    NdnLenField(),
                    PacketField("value", ECDSASignature(), ECDSASignature)
                  ]

class ECDSASignatureValue(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
#    name = "ECDSA PacketList"
    NdnType = TYPES['SignatureValue']
    PktCls  = ECDSASignature

class DigestSha256SignatureValue(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = TYPES['SignatureValue']
    PktCls  = DigestSha256

class RsaSignatureValue(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
    NdnType = TYPES['SignatureValue']
    PktCls  = RsaSignature

class InterestSignatureInfo(NdnBasePacket):
    TYPES_TO_CLS = {
                     TYPES["SignatureType"] : SignatureType,
                     TYPES["KeyLocator"] : KeyLocator,
                     TYPES["SignatureNonce"] : SignatureNonce,
                     TYPES["SignatureTime"] : SignatureTime,
                     TYPES["SignatureSeqNum"] : SignatureSeqNum
                   }

    fields_desc = [
                    NdnTypeField(TYPES['InterestSignatureInfo']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, SignatureInfo.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class InterestSignatureValue(SignatureValue):
    NdnType = TYPES["InterestSignatureValue"]

SIG_TYPE_TO_CLS = {
    0 : DigestSha256SignatureValue,
    1 : RsaSignatureValue,
    3 : ECDSASignatureValue
}

class Interest(NdnBasePacket):
    name = "Interest"

    TYPES_TO_CLS = {
                     TYPES["Name"] : Name,
                     TYPES["CanBePrefix"] : CanBePrefix,
                     TYPES["MustBeFresh"] : MustBeFresh,
                     TYPES["ForwardingHint"] : ForwardingHint,
                     TYPES["Nonce"] : Nonce,
                     TYPES["InterestLifetime"] : InterestLifetime,
                     TYPES["HopLimit"] : HopLimit,
                     TYPES["ApplicationParameters"] : ApplicationParameters,
                     TYPES["InterestSignatureInfo"] : InterestSignatureInfo,
                     TYPES["InterestSignatureValue"] : InterestSignatureValue,
                   }

    fields_desc = [
                    NdnTypeField(TYPES['Interest']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, Interest.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

    def guess_ndn_packets(self, lst, cur, remain, types_to_cls, default=Raw):
        '''
        Override to decode:
            - InterestSignatureValue class once InterestSignatureType is decoded
        '''
        blk = TypeBlock(remain)
        if blk.type == TYPES["InterestSignatureValue"]:
            if type(cur) == InterestSignatureInfo:
                sigtype = cur["SignatureType"].value
                if sigtype in SIG_TYPE_TO_CLS and sigtype is not None:
                   return SIG_TYPE_TO_CLS[sigtype]
                return InterestSignatureValue

        if blk.type in types_to_cls:
            return types_to_cls[blk.type]
        return default

NAME_URI_TO_CONTENT_CLS = {}
def bind_content_cls_to_data_name(name_uri, content_val_cls):
    # type: (str, Packet) -> None
    """
    Creates a mapping from a NameURI to Content class with value as content_val_cls
    This Content class is then used during Data packet dissection when NameURI matches.

        * name_uri: str such as /localhost/nfd/fib/list
        * content_val_cls: cls such as NfdFib
    """
    class Content(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
        NdnType = TYPES["Content"]
        PktCls  = content_val_cls
    NAME_URI_TO_CONTENT_CLS[name_uri] = Content

def bind_content_cls_dict_to_data_name(name_uri, type_to_cls):
    # type: (str, dict[int, Packet]) -> None
    """
    Creates a mapping from a NameURI to Content class which uses
    the given type_to_cls dictionary to guess the value of the Content.
    This Content class is then used during Data packet dissection when NameURI matches.

        * name_uri: str such as /localhost/nfd/status/general
        * type_to_cls: dict such as
          {
              NFD_GENERAL_DATASETS_CLS_TO_TYPE["NfdVersion"]: NfdVersion,
              NFD_GENERAL_DATASETS_CLS_TO_TYPE["StartTimestamp"]: StartTimestamp
          }
    """
    class Content(NdnBasePacket, metaclass=_NdnPacketList_metaclass):
        NdnType   = TYPES["Content"]
        TypeToCls = type_to_cls
    NAME_URI_TO_CONTENT_CLS[name_uri] = Content

class Data(NdnBasePacket):

    TYPES_TO_CLS = {
                     TYPES["Name"] : Name,
                     TYPES["MetaInfo"] : MetaInfo,
                     TYPES["Content"] : Content,
                     TYPES["SignatureInfo"]: SignatureInfo,
                     TYPES["SignatureValue"]: SignatureValue
                   }

    fields_desc = [
                    NdnTypeField(TYPES["Data"]),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, Data.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

    def guess_ndn_packets(self, lst, cur, remain, types_to_cls, default=Raw):
        '''
        Override to decode:
            - Content class for the Name once Name is decoded
            - SignatureValue class once SignatureType is decoded
        '''
        blk = TypeBlock(remain)
        if blk.type == TYPES["Content"]:
            if type(cur) == MetaInfo:
                for mi_pkt in cur.value:
                    if type(mi_pkt) == ContentType and \
                       mi_pkt.value == 2: # Key
                        return SubjectPublicKeyInfoContent
            # print('what: ', type(cur), cur.value)
            # print('what lst: ', type(lst), lst)
            for l in lst + [cur]:
                if not isinstance(l, Name):
                    continue

                # Loop since Probably will be a prefix
                cls_to_return = None
                longest_prefix_len = 0
                for n in NAME_URI_TO_CONTENT_CLS:
                    is_prefix, n_num_comp = l.is_prefix_of(n)
                    # print(n, l.to_uri(), is_prefix, n_num_comp)

                    if is_prefix is True:
                        if n_num_comp > longest_prefix_len:
                            longest_prefix_len = n_num_comp
                            cls_to_return = NAME_URI_TO_CONTENT_CLS[n]

                if cls_to_return is not None:
                    return cls_to_return
        if blk.type == TYPES["SignatureValue"]:
            if isinstance(cur, SignatureInfo):
                sigtype = cur["SignatureType"].value
                if sigtype in SIG_TYPE_TO_CLS and sigtype is not None:
                    return SIG_TYPE_TO_CLS[sigtype]
                return SignatureValue

        if blk.type in types_to_cls:
            return types_to_cls[blk.type]
        return default

class Certificate(Data):
    name = "Certificate"

class LinkContent(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(TYPES["Content"]),
                    NdnLenField(),
                    PacketLenField("value", "", Name, length_from=lambda pkt: pkt.length)
                  ]

class LinkObject(Data):

    TYPES_TO_CLS = {
                     TYPES["Name"] : Name,
                     TYPES["MetaInfo"] : MetaInfo,
                     TYPES["Content"] : LinkContent,
                     TYPES["SignatureInfo"]: SignatureInfo,
                     TYPES["SignatureValue"]: SignatureValue
                   }

    fields_desc = [
                    NdnTypeField(TYPES['Data']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     # Do we use guess packets from Data here now, or since ContentType is known that is not needed
                                     # But SignatureValue still needs to be decoded
                                     # If someone is testing malformed LinkContent they can put anything
                                     # so maybe better to use Data's guess_ndn_packtets
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, LinkObject.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class Sequence(NdnBasePacket):

    fields_desc = [
        NdnTypeField(LP_TYPES["Sequence"]),
        NdnLenField(),
        NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
    ]

class TxSequence(NdnBasePacket):

    fields_desc = [
        NdnTypeField(LP_TYPES["TxSequence"]),
        NdnLenField(),
        NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
    ]

class FragIndex(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(LP_TYPES['FragIndex']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class FragCount(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(LP_TYPES['FragCount']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length)
                  ]

class NackReason(NdnBasePacket):

    NACK_REASONS = {
                       0 : "None",
                      50 : "Congestion",
                     100 : "Duplicate",
                     150 : "NoRoute"
                   }

    fields_desc = [
                    NdnTypeField(LP_TYPES['NackReason']),
                    NdnLenField(),
                    NonNegativeIntField("value", 0, length_from=lambda pkt: pkt.length, enum=NACK_REASONS)
                  ]

class Nack(NdnBasePacket):

    fields_desc = [
                    NdnTypeField(LP_TYPES['Nack']),
                    NdnLenField(),
                    PacketListField("value", "", NackReason, length_from=lambda pkt: pkt.length)
                  ]

class Fragment(NdnBasePacket):
    TYPES_TO_CLS = {
        TYPES["Interest"] : Interest,
        TYPES["Data"] : Data
    }

    fields_desc = [
                    NdnTypeField(LP_TYPES['Fragment']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, Fragment.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class PitToken(NdnBasePacket):
    fields_desc = [
        NdnTypeField(LP_TYPES["PitToken"]),
        NdnLenField(),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length)
    ]

class Ack(NonNegativeIntBase):
    NdnType = LP_TYPES["Ack"]

class NextHopFaceId(NonNegativeIntBase):
    NdnType = LP_TYPES["NextHopFaceId"]

class LpPacket(NdnBasePacket):
    TYPES_TO_CLS = {
        TYPES["Interest"] : Interest,
        TYPES["Data"] : Data,
        LP_TYPES["Nack"] : Nack,
        LP_TYPES["Fragment"] : Fragment,
        LP_TYPES["Sequence"] : Sequence,
        LP_TYPES["FragIndex"] : FragIndex,
        LP_TYPES["FragCount"] : FragCount,
        LP_TYPES["PitToken"] : PitToken,
        LP_TYPES["TxSequence"] : TxSequence,
        LP_TYPES["Ack"] : Ack,
        LP_TYPES["NextHopFaceId"] : NextHopFaceId
    }

    fields_desc = [
                    NdnTypeField(LP_TYPES['LpPacket']),
                    NdnLenField(),
                    PacketListField("value", [],
                                     next_cls_cb=lambda pkt, lst, cur, remain
                                     : pkt.guess_ndn_packets(lst, cur, remain, LpPacket.TYPES_TO_CLS),
                                     length_from=lambda pkt: pkt.length)
                  ]

class NdnGuessPacket(Packet):
    'Dummy packet for guessing NDN packets via bind_layers'

    TYPES_TO_CLS = {
        TYPES["Interest"] : Interest,
        TYPES["Data"] : Data,
        LP_TYPES["LpPacket"] : LpPacket
    }

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Type[Packet]
        if _pkt is not None:
            blk = TypeBlock(_pkt)
            if blk.type in NdnGuessPacket.TYPES_TO_CLS:
                return NdnGuessPacket.TYPES_TO_CLS[blk.type]
        return Block

bind_layers(Ether, NdnGuessPacket, type=0x8624)
bind_layers(UDP, NdnGuessPacket, sport=6363)
bind_layers(UDP, NdnGuessPacket, dport=6363)
bind_layers(UDP, NdnGuessPacket, sport=56363)
bind_layers(UDP, NdnGuessPacket, dport=56363)
bind_layers(TCP, NdnGuessPacket, sport=6363)
bind_layers(TCP, NdnGuessPacket, dport=6363)
