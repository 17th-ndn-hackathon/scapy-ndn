import struct

from scapy.all import Field, Packet, XByteField, StrField, StrLenField, \
                      PacketListField, conf, StrFixedLenField, \
                      PacketField, XIntField

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
          "SegmentNameComponent"    : 32, # 0x20
          "ByteOffsetNameComponent" : 33, # 0x21
          "VersionNameComponent"    : 34, # 0x22
          "TimestampNameComponent"  : 35, # 0x23
          "SequenceNumNameComponent": 36, # 0x24
        }

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
        if x is None:
            fld, fval = pkt.getfield_and_val(self.name)
            if x is None:
                x = fld.i2len(pkt, fval)
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
                 _ndn_uri=False,
                 **fields  # type: Any
                ):

        if "value" in fields:
            # print("_ndn_uri: ", _ndn_uri, "value: ", fields["value"])
            if isinstance(fields["value"], str) and _ndn_uri:
                fields["type"], fields["value"] = NameComponent.from_escaped_string(fields["value"])
            elif isinstance(fields["value"], int):
                fields["length"], fields["value"] = NameComponent.from_number(fields["value"])
            elif isinstance(fields["value"], float):
                fields["value"] = NameComponent.from_double(fields["value"])

        Packet.__init__(self, _pkt, post_transform, _internal, _underlayer, **fields)

    def guess_payload_class(self, p):
        return conf.padding_layer

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
    def _unescape(input):
        unescaped = ""
        i = 0
        while i < len(input):
            if input[i] == "%" and i + 2 < len(input):
                hi = NameComponent._from_hex_char(ord(input[i + 1]))
                lo = NameComponent._from_hex_char(ord(input[i + 2]))

                if hi < 0 or lo < 0:
                    unescaped += input[i] + input[i + 1] + input[i + 2]
                else:
                    unescaped += chr(hi << 4 | lo)
                i += 2
            else:
                unescaped += input[i]
            i += 1
        return unescaped

    @staticmethod
    def from_escaped_string(input, use_known=True):
        # Could use urllib only if python3

        # Don't handle . or .. (should be able to construct invalid packets in Scapy)
        if "=" not in input:
            return TYPES['GenericNameComponent'], NameComponent._unescape(input)
        else:
            splitName = input.split("=")
            # Don't care whether nameType is in valid range
            try:
                nameType = int(splitName[0])
            except ValueError:
                nameType = splitName[0]

            if use_known:
                if nameType in COMP_TYPES:
                    nameType = COMP_TYPES[nameType]

            return nameType, NameComponent._unescape("".join(input.split("=")[1:]))

    @staticmethod
    def from_number(x):
        if x < 0 or not isinstance(x, int):
            x = 0

        if x <= 255:
            s = struct.pack(">B", x)
            l = 1
        elif x < 65535:
            s = struct.pack(">H", x)
            l = 2
        elif x < 4294967295:
            s = struct.pack(">L", x)
            l = 4
        else:
            s = struct.pack(">Q", x)
            l = 8
        return l, s

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
    def from_number_with_marker():
        pass

    @staticmethod
    def from_version():
        pass

    @staticmethod
    def from_timestamp():
        pass

    @staticmethod
    def from_sequence_number():
        pass

    @staticmethod
    def from_implicit_sha256_digest():
        pass

    @staticmethod
    def from_parameters_sha256_digest():
        pass

# Following two classes given for convenience:
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

#class Interest(Packet):
#    name = "Interest"
#    default_name = Name(value=NameComponent(value="test1"))

#    fields_desc = [
#                    NdnTypeField(TYPES['Interest']),
#                    NdnLenField(),
                    # InterestName and not name. Otherwise it conflicts
                    # with name field of scapy Packet (base) class
#                    PacketField("interestName", Name(), Name),
#                    StrLenField("canBePrefix", "", 1),
#                    StrLenField("mustBeFresh", "", 1),
#                    StrLenField("nonce", "", 1),
#                  ]