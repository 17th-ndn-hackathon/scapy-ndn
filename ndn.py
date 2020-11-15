import struct

from scapy.all import Field, Packet, XByteField, StrLenField, PacketListField, conf

class NdnLenField(Field):
    __slots__ = [ "length_of" ]

    def __init__(self, name, default, length_of, fmt="!H"):  # noqa: E501
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of

    def i2m(self, pkt, x):
        if x is None:
            fld, fval = pkt.getfield_and_val(self.length_of)
            x = fld.i2len(pkt, fval)
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

TYPES = { 'Name': 0x07, 'GenericNameComponent': 0x08 }

class NameComponent(Packet):
    name = "Name Component"

    fields_desc = [
                    XByteField("type", TYPES['GenericNameComponent']),
                    NdnLenField("length", None, length_of="value"),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

    def guess_payload_class(self, p):
        return conf.padding_layer

class Name(Packet):
    name = "Name"

    fields_desc = [
                    XByteField("type", TYPES['Name']),
                    NdnLenField("length", None, length_of="value"),
                    PacketListField("value", [],
                                    NameComponent,
                                    count_from=lambda pkt : Name.count_components(pkt))
                  ]

    def count_components(pkt):
        print("sjvdbjhsb")
        return 2