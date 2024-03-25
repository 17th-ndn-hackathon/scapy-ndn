import socket
import time
import os
import sys
import base64
import hashlib
import random

from scapy.all import *
from scapyndn.pkt import *
from scapyndn.contents.nfd import *

from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec

class UnixSocket(SuperSocket):
    desc = "Unix sockets using Raw sockets (PF_INET/SOCK_RAW)"

    def __init__(self, unix_socket_file="/var/run/nfd.sock"):
        self.outs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.ins = self.outs
        self.outs.connect(unix_socket_file)

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        return NdnGuessPacket, self.ins.recv(x), None

name_to_reg = Name(value=NameComponent(value="test10") / NameComponent(value="ndn"))

cp = ControlParameters(value=name_to_reg / FaceId(value=259) / Origin(value=255) / Cost(value=100) / Flags(value=1))

n_v = NameComponent(value="localhost") / NameComponent(value="nfd") / \
      NameComponent(value="rib") / NameComponent(value="register") / NameComponent(value=cp)

interest_nonce = Nonce(value=random.randint(0, 4294967295)) #0xbb801efe)
empty_app_params = ApplicationParameters(length=0, value="")

interest_sig_info = InterestSignatureInfo(
           value = SignatureType(value=3) /
                   KeyLocator(value=
                       Name(value=
                           NameComponent(value="localhost") /
                           NameComponent(value="operator") /
                           NameComponent(value="KEY") /
                           NameComponent(value=b'\xe7B\x1bx"\x91\xed\xe0') /
                           NameComponent(value="self") /
                           VersionNameComponent(value=1699495954653)
                       )
                   ) /
                   SignatureNonce(value=os.urandom(8)) /
                   SignatureTime(value=datetime.now())
                   #SignatureTime(value=1702254892499)
                   #SignatureNonce(value=b'^\xdd\x0c\xacn\x1e\xde\xca') /
                   #SignatureNonce(value=b'\x1e\x90\xfdI\xff\x961\xbd') /
        )

# ================================Calculate Signature===================================
# The cryptographic signature contained in InterestSignatureValue covers all the NameComponent elements in the Interest’s Name up to,
# but not including, ParametersSha256DigestComponent, and the complete TLV elements starting from ApplicationParameters up to, but not including,
# InterestSignatureValue. These TLV elements are hereby referred to as the "signed portion" of an Interest packet.

interest_signed_portion = raw(n_v / empty_app_params / interest_sig_info)

priv_key_dump = None
with open("/path/to/.ndn/ndnsec-key-file/<hash>.privkey") as f:
    priv_key_dump = base64.b64decode(f.read().strip())

priv_key = load_der_private_key(priv_key_dump, password=None)
print(priv_key)

#help(priv_key)
#print("Public key: ", priv_key.public_key())

print(priv_key.curve)
print(priv_key.key_size)

signature = priv_key.sign(interest_signed_portion, ec.ECDSA(hashes.SHA256())) # works, but how to extract sha256 signature out of it?
interest_sig_val = InterestSignatureValue(value=signature)

public_key = priv_key.public_key()
t = public_key.verify(signature, interest_signed_portion, ec.ECDSA(hashes.SHA256()))
print(t)

# ================================Calculate Signature===================================

# ================================Calculate Parameters Sha256 Digest===================================
# The parameters digest component (ParametersSha256DigestComponent) contains the SHA-256 digest computed over the portion
# of an Interest starting from and including the ApplicationParameters element until the end of the Interest

params_digest_portion = empty_app_params / interest_sig_info / interest_sig_val

chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash)
hasher.update(raw(params_digest_portion))
params_digest = hasher.finalize()
print(params_digest)
# ================================Calculate Parameters Sha256 Digest===================================

interest_name = Name(value = n_v / ParametersSha256DigestComponent(value=params_digest))
i = Interest(value=interest_name / interest_nonce / empty_app_params / interest_sig_info / interest_sig_val)
i.show2()
hexdump(i)

us = UnixSocket()

t = AsyncSniffer(opened_socket=us, prn=lambda x: hexdump(x))
t.start()
sendp(i, socket = us)
time.sleep(0.1)
t.stop()
d = t.results[0]
print(type(d))
d.show2()
print(raw(d))
