from scapy.all import Field, Packet, XByteField, StrLenField, struct

class NdnLenField(Field):
    __slots__ = ["length_of"]

    def __init__(self, name, default, length_of, fmt="!H"):  # noqa: E501
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of

    def i2m(self, pkt, x):
        if x is None:
            fld, fval = pkt.getfield_and_val(self.length_of)
            #print(fld, fval)
            x = fld.i2len(pkt, fval)
            #print(x)
        return x

    def addfield(self, pkt, s, val):
        x = self.i2m(pkt, val)
        print(x, type(x), val, pkt, s)
        if x < 253:
            return s + struct.pack("1s", x.to_bytes(1, byteorder='big'))
        elif x < 65536:
            return s + b"\xFD" + struct.pack("2s", x.to_bytes(2, byteorder='big'))
        elif x < 4294967296:
            return s + b"\xFE" + struct.pack("4s", x.to_bytes(4, byteorder='big'))
        else:
            return s + b"\xFF" + struct.pack("8s", x.to_bytes(8, byteorder='big'))

    def getfield(self, pkt, s):
        return s[self.sz:], self.m2i(pkt, self.struct.unpack(s[:self.sz])[0])

class NameComponent(Packet):
    name = "Name Component"

    fields_desc = [
                    XByteField("type", 0x008),
                    NdnLenField("length", None, length_of="value"),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]

    def guess_payload_class(self, p):
        return conf.padding_layer

class Name(Packet):
    name = "Name"

    fields_desc = [
                    XByteField("type", 0x008),
                    NdnLenField("length", None, length_of="value"),
                    StrLenField("value", "", length_from=lambda pkt: pkt.length)
                  ]
