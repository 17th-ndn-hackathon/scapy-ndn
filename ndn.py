import struct
from datetime import datetime, timedelta

from scapy.all import Field, Packet, XByteField, StrField, StrLenField, \
                      PacketListField, conf, StrFixedLenField, \
                      PacketField, XIntField, bind_layers, ConditionalField, RawVal

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
          "ForwardingHint"                 : 30, # 0x1E
          "Nonce"                          : 10, # 0x0A
          "InterestLifetime"               : 12, # 0x0C
        }

TYPED_NAME_COMP = {
          "SegmentNameComponent"    : 33, # 0x21
          "ByteOffsetNameComponent" : 34, # 0x22
          "VersionNameComponent"    : 35, # 0x23
          "TimestampNameComponent"  : 36, # 0x24
          "SequenceNumNameComponent": 37, # 0x25
        }

NUM_TO_TYPES = {v: k for k, v in TYPES.items()}

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

    def __init__(self, name="length", default=None, fmt="!H"):  # noqa: E501
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
        #for field in pkt.fields_desc:
        #    if field.name == "type":
        #        print("---->", pkt.getfield_and_val(field.name))
        #print("Adding field: ", s, val)
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
        if pkt.getfield_and_val("type")[-1] is None:
            print("Yeko", s)
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
        NdnLenField.__init__(self, name, default, fmt)

    def i2m(self, pkt, x):
        print("i2m", x)
        if isinstance(x, str) and x in COMP_TYPES:
            x = COMP_TYPES[x]

        if self.name in TYPES and x:
            return TYPES[self.name]

        if x is None:
            print("return empty from ndntypefield")
            return b""
        return x

    def i2repr(self, pkt, x):
        # print("i2repr: {}".format(x))
        #if x in NUM_TO_TYPES:
        #    #print(NUM_TO_TYPES[x])
        #    return "{} [{}]".format(NUM_TO_TYPES[x], x)
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

        """
        Go over s one by one, if any val is not in packet, return None since we are unable to
        determine. If val is in packet but out of order, remove the current value, return the reassbled
        rest_of_packet
        """

        if self.name == "MustBeFresh":
            print(s)
            print("Must be fresh detected: ", rest_of_pkt, val)
            for f in pkt.fields_desc:
                print(f.name, pkt.getfieldval(f.name))
        if self.valid_types is not None:
            if val not in self.valid_types:
                return s, None

        #if self.default != val:
        #    return s, None

        # i.e. self.name != (generic) type
        #if self.name in TYPES:
        #    print("Getting field: ", s, self.name, self.default)
        #    if bytes([TYPES[self.name]]) not in s:
        #        return s, None
        #    else:
        #        b = bytes([TYPES[self.name]])
        #        i = s.index(b)
        #        print("--->", i)
        #        if i != 0: # out-of-order field
        #            print(s)
            #    return s, None
        return rest_of_pkt, val

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

    def guess_payload_class(self, p):
        return conf.padding_layer

class CanBePrefix(NdnTypeField):

    def __init__(self, fmt="!H"):  # noqa: E501
        NdnTypeField.__init__(self, "", "CanBePrefix", [TYPES["CanBePrefix"]], fmt)

class MustBeFresh(NdnTypeField):

    def __init__(self, fmt="!H"):  # noqa: E501
        NdnTypeField.__init__(self, "", "MustBeFresh", [TYPES["MustBeFresh"]], fmt)

class Nonce(Packet):
    name = "Nonce"

    fields_desc = [
                    NdnTypeField(TYPES['Nonce'], valid_types=[TYPES['Nonce']]),
                    NdnLenField(default=4),
                    ConditionalField(XIntField("value", 2), lambda pkt : pkt.type != None)
                  ]

class ForwardingHint(Packet):
    name = "ForwardingHint"

    fields_desc = [
                    NdnTypeField(TYPES['ForwardingHint']),
                    NdnLenField(),
                    ConditionalField(StrFixedLenField("value", ""), lambda pkt : pkt.type != None)
                  ]

class InterestLifetime(Packet):
    name = "InterestLifetime"

    fields_desc = [
                    NdnTypeField(TYPES['InterestLifetime']),
                    NdnLenField(),
                    StrFixedLenField("value", "")
                  ]

class Interest(Packet):
    name = "Interest"

    fields_desc = [
                    NdnTypeField(TYPES['Interest']),
                    NdnLenField(),
                    # interestName and not name. Otherwise it conflicts
                    # with name field of scapy Packet (base) class
                    PacketField("interestName", Name(), Name),
                    #ConditionalField(CanBePrefix(), lambda pkt : Interest.test(pkt)),
                    CanBePrefix(),
                    MustBeFresh(),
                    PacketField("Nonce", "", Nonce),
                    #PacketField("canBePrefix", "", CanBePrefix),
                    #StrField("canBePrefix", ""),
                    #StrField("mustBePrefix", ""),
                    #StrFixedLenField("forwardingHint", ""),
                    #StrFixedLenField("interestLifetime", "")
                  ]

    #def do_dissect(self, s):
    #    print("---------------------->Interst Dissect: {}".format(s))
    #    _raw = s
    #    self.raw_packet_cache_fields = {}
    #    for f in self.fields_desc:
    #        if not s:
    #            print("Interest Dissect Break")
    #            break
    #        print("-=======-", s, f, type(f))
    #        s, fval = f.getfield(self, s)

    #        print("f.name: {}, s: {}, fval: {}".format(f.name, s, fval))
            # We need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
    #        if f.islist or f.holds_packets or f.ismutable:
    #            self.raw_packet_cache_fields[f.name] = f.do_copy(fval)

            #keyname = f.name
            #if f.name in TYPES:
                # Out-of-expected-order fields are received, let's fix that
            #    print("TYPES[f.name], fval: ", TYPES[f.name], fval)
            #    if TYPES[f.name] != fval:
                    #self.fields[f.name] == ""
            #        break
                    #if isinstance(fval, int) and fval in NUM_TO_TYPES:
                    #if isinstance(fval, int):
                    #    print("Yello: {}".format(NUM_TO_TYPES[fval]))
                        #keyname = NUM_TO_TYPES[fval]
                    #    self.fields[NUM_TO_TYPES[fval]] = fval
                    #    continue
            #if f.name in self.fields:
    #        self.fields[f.name] = fval

    #    self.raw_packet_cache = _raw[:-len(s)] if s else _raw
    #    self.explicit = 1
    #    return s

    @staticmethod
    def test(pkt):
        print("Hello")
        return True
