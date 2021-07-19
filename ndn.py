import struct
from datetime import datetime, timedelta

from scapy.all import Field, Packet, XByteField, StrField, StrLenField, \
                      PacketListField, conf, StrFixedLenField, \
                      PacketField, XIntField, bind_layers

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
          "Name"                           : 7,
          "GenericNameComponent"           : 8,
          "CanBePrefix"                    : 33, # 0x21
          "MustBeFresh"                    : 18, # 0x12
          "Nonce"                          : 10, # 0x0a
        }

TYPED_NAME_COMP = {
          "GenericNameComponent"    : 8,
          "SegmentNameComponent"    : 33, # 0x21
          "ByteOffsetNameComponent" : 34, # 0x22
          "VersionNameComponent"    : 35, # 0x23
          "TimestampNameComponent"  : 36, # 0x24
          "SequenceNumNameComponent": 37, # 0x25
        }

NUM_TO_TYPED_NAME_COMP = {v: k for k, v in TYPED_NAME_COMP.items()}

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

    def __init__(self, name="length", default=None, fmt="!H"):  # noqa: E501
        Field.__init__(self, name, default, fmt)

    def i2m(self, pkt, x):
        if not pkt:
            return x

        if x is None:
            for field in pkt.fields_desc:
                if field.name != "type" and field.name != "length":
                    fld, fval = pkt.getfield_and_val(field.name)
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

class NdnTypeField(NdnLenField):
    def __init__(self, default, name="type", fmt="!H"):  # noqa: E501
        NdnLenField.__init__(self, name, default, fmt)

    def i2m(self, pkt, x):
        if isinstance(x, str) and x in COMP_TYPES:
            x = COMP_TYPES[x]

        if x is None:
            fld, fval = pkt.getfield_and_val(self.name)
            if x is None:
                x = fld.i2len(pkt, fval)
        return x

    def i2repr(self, pkt, x):
        if x in NUM_TO_TYPED_NAME_COMP:
            return "{} [{}]".format(NUM_TO_TYPED_NAME_COMP[x], x)
        return x

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
                 _unescape=True,
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

class Name(Packet):
    name = "Name"

    fields_desc = [
                    NdnTypeField(TYPES['Name']),
                    NdnLenField(),
                    # Check only for valid NameComponents when reading?
                    PacketListField("value", NameComponent(), NameComponent,
                                    length_from=lambda pkt : pkt.length)
                  ]

class CanBePrefix(Packet):
    name = "CanBePrefix"

    fields_desc = [ NdnTypeField(TYPES['CanBePrefix']) ]

class MustBeFresh(Packet):
    name = "MustBeFresh"

    fields_desc = [ NdnTypeField(TYPES['MustBeFresh']) ]

class Nonce(Packet):
    name = "Nonce"

    fields_desc = [
                    NdnTypeField(TYPES['Nonce']),
                    NdnLenField(default=4),
                    XIntField("value", 2)
                  ]

class Interest(Packet):
    name = "Interest"
#    default_name = Name(value=NameComponent(value="test1"))

    fields_desc = [
                    NdnTypeField(TYPES['Interest']),
                    NdnLenField(),
                    # InterestName and not name. Otherwise it conflicts
                    # with name field of scapy Packet (base) class
                    PacketField("interestName", Name(), Name),
                    StrLenField("canBePrefix", "", 1),
                    StrLenField("mustBeFresh", "", 1),
                    StrLenField("nonce", "", 1),
                  ]
