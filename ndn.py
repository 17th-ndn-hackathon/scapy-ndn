import struct

from scapy.all import Field, Packet, XByteField, StrLenField, \
                      PacketListField, conf, StrFixedLenField, \
                      PacketField

TYPES = {
          'ImplicitSha256DigestComponent': 0x01,
          'ParametersSha256DigestComponent': 0x02,
          'Interest': 0x05,
          'Name': 0x07,
          'GenericNameComponent': 0x08,
          'CanBePrefix': 0x21, # 33
          'MustBeFresh': 0x12, # 18
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
                    NdnLenField(),
                    StrLenField("value", "test", length_from=lambda pkt: pkt.length)
                  ]

    def guess_payload_class(self, p):
        return conf.padding_layer

# Following two classes given for convenience:
class ImplicitSha256DC(NameComponent):

    fields_desc = [
                    NdnTypeField(TYPES['ImplicitSha256DigestComponent']),
                    NdnLenField("32"),
                    StrFixedLenField("value", "", 32)
                  ]

class ParametersSha256DC(NameComponent):

    fields_desc = [
                    NdnTypeField(TYPES['ParametersSha256DigestComponent']),
                    NdnLenField("32"),
                    StrFixedLenField("value", "", 32)
                  ]

class Name(Packet):
    name = "Name"

    fields_desc = [
                    NdnTypeField(TYPES['Name']),
                    NdnLenField(),
                    PacketListField("value", NameComponent(), NameComponent,
                                    length_from=lambda pkt : pkt.length)
                  ]

class Interest(Packet):
    name = "Interest"
    default_name = Name(value=NameComponent(value="test1"))

    fields_desc = [
                    NdnTypeField(TYPES['Interest']),
                    NdnLenField(),
                    # InterestName and not name. Otherwise it conflicts
                    # with name field of scapy Packet (base) class
                    PacketField("InterestName", Name(), Name),
                    StrLenField("CanBePrefix", "", 1)
                  ]