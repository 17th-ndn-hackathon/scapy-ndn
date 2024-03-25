import base64
import sys

from scapy.all import *
from scapyndn.pkt import *
from scapyndn.contents.nfd import *

from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec

p = rdpcap("5-nfdc-fib-register.pcap")

t = p[0]

i = t["Interest"]
i.show2()

# Parameters Digest calculation

#The parameters digest component (ParametersSha256DigestComponent) contains the SHA-256 digest computed over the portion
# of an Interest starting from and including the ApplicationParameters element until the end of the Interest

digest_portion = None
for layer in i.value:
    if str(layer) == "Name" or str(layer) == "Nonce":
        continue
    print(layer)
    if digest_portion is None:
        digest_portion = layer
    else:
        digest_portion /= layer

# digest_portion.show2()

chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash)
hasher.update(raw(digest_portion))
params_digest = hasher.finalize()
print(params_digest)

# Verify signature

signed_portion = None
signature = None
for layer in i.value:
    if str(layer) == "ECDSASignatureValue":
        signature = raw(layer.value[0])
        continue
    if str(layer) == "Nonce":
        continue
    if str(layer) == "Name":
        for nc in layer.value:
            if isinstance(nc, ParametersSha256DigestComponent):
                continue
            print(nc)
            if signed_portion is None:
                signed_portion = nc
            else:
                signed_portion /= nc
        continue
    print(layer)
    signed_portion /= layer

priv_key_dump = None
with open("/path/to/.ndn/ndnsec-key-file/<hash>.privkey") as f:
    priv_key_dump = base64.b64decode(f.read().strip())

priv_key = load_der_private_key(priv_key_dump, password=None)
# print(priv_key)
public_key = priv_key.public_key()
t = public_key.verify(signature, raw(signed_portion), ec.ECDSA(hashes.SHA256()))
