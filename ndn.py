import struct

from scapy.all import Field, Packet, XByteField, StrLenField, \
                      PacketListField, conf, StrFixedLenField

TYPES = {
          'ImplicitSha256DigestComponent': 0x01,
          'ParametersSha256DigestComponent': 0x02,
          'Name': 0x07,
          'GenericNameComponent': 0x08
        }

class NdnLenField(Field):

    def __init__(self, name, default, fmt="!H"):  # noqa: E501
        Field.__init__(self, name, default, fmt)

    def i2m(self, pkt, x):
        if x is None:
            for field in pkt.fields_desc:
                if field.name != "type" and field.name != "length":
                    fld, fval = pkt.getfield_and_val(field.name)
                    if x is None:
                        x = fld.i2len(pkt, fval)
                    else:
                        x += fld.i2len(pkt, fval)
        #elif isinstance(x, str):
        #    return bytes_encode(x)
        return x

    def addfield(self, pkt, s, val):
        x = self.i2m(pkt, val)
        if x < 253:
            return s + struct.pack(">B", x)
        elif x < 65536:
            return s + b"\xFD" + struct.pack(">H", x)
        elif x < 4294967296:
            return s + b"\xFE" + struct.pack(">L", x)
        else:
            return s + b"\xFF" + struct.pack(">Q", x)

    def getfield(self, pkt, s):
        x = ord(s[:self.sz - 1])
        if x < 253:
            return s[1:], self.m2i(pkt, struct.unpack(">B", s[:1])[0])
        elif x < 65536:
            return s[3:], self.m2i(pkt, struct.unpack(">H", s[:2])[0])
        elif x < 4294967296:
            return s[5:], self.m2i(pkt, struct.unpack(">L", s[:4])[0])
        else:
            return s[7:], self.m2i(pkt, struct.unpack(">Q", s[:8])[0])

class NdnTypeField(NdnLenField):
    def __init__(self, name, default, fmt="!H"):  # noqa: E501
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
                    NdnTypeField("type", TYPES['GenericNameComponent']),
                    NdnLenField("length", None),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

    def guess_payload_class(self, p):
        return conf.padding_layer

# Following two classes given for convenience:
class ImplicitSha256DigestComponent(NameComponent):

    fields_desc = [
                    XByteField("type", TYPES['ImplicitSha256DigestComponent']),
                    XByteField("length", 32),
                    StrFixedLenField("value", "", 32)
                  ]

class ParametersSha256DigestComponent(NameComponent):

    fields_desc = [
                    XByteField("type", TYPES['ParametersSha256DigestComponent']),
                    XByteField("length", 32),
                    StrFixedLenField("value", "", 32)
                  ]

class Name(Packet):
    name = "Name"

    fields_desc = [
                    XByteField("type", TYPES['Name']),
                    NdnLenField("length", None),
                    PacketListField("value", [],
                                    NameComponent,
                                    count_from=lambda pkt : Name.count_components(pkt))
                  ]

    def count_components(pkt):
        print("sjvdbjhsb")
        return 2