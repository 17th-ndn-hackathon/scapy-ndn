# -*- mode: python -*-

import sqlite3
import os
from hashlib import sha256
import base64
from datetime import datetime
import random

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import hashes

from scapy.compat import raw

from scapyndn.pkt import Name, Certificate, \
    InterestSignatureInfo, InterestSignatureValue, \
    KeyLocator, SignatureNonce, SignatureTime, ApplicationParameters, \
    ParametersSha256DigestComponent, Nonce, Interest

def get_default_cert_raw():
    home_dir = os.getenv("HOME")

    con = sqlite3.connect("{}/.ndn/pib.db".format(home_dir))
    cur = con.cursor()

    for row in cur.execute("SELECT * FROM certificates"):
        if row[-1] == 1:
            return row[3]

def get_default_priv_key():
    home_dir = os.getenv("HOME")

    con = sqlite3.connect("{}/.ndn/pib.db".format(home_dir))
    cur = con.cursor()

    for row in cur.execute("SELECT * FROM keys"):
        if row[-1] == 1:
            priv_file = sha256(row[2]).digest().hex()
            priv_file_path = "{}/.ndn/ndnsec-key-file/{}.privkey".format(home_dir, priv_file)
            with open(priv_file_path) as f:
                priv_key_dump = base64.b64decode(f.read().strip())
                return load_der_private_key(priv_key_dump, password=None)

def get_signed_interest_with_default_key(interest_name_val):
    default_key_cert = Certificate(get_default_cert_raw())
    interest_sig_info = InterestSignatureInfo(value=
        default_key_cert["SignatureInfo"]["SignatureType"] /
        KeyLocator(value=default_key_cert["Name"]) /
        SignatureNonce(value=os.urandom(8)) /
        SignatureTime(value=datetime.now())
    )

    empty_app_params = ApplicationParameters(length=0, value="")

    interest_signed_portion = raw(interest_name_val / empty_app_params / interest_sig_info)
    priv_key = get_default_priv_key()
    signature = priv_key.sign(interest_signed_portion, ec.ECDSA(hashes.SHA256()))
    interest_sig_val = InterestSignatureValue(value=signature)

    params_digest_portion = empty_app_params / interest_sig_info / interest_sig_val
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(raw(params_digest_portion))
    params_digest = hasher.finalize()

    interest_nonce = Nonce(value=random.randint(0, 4294967295))

    interest_name = Name(value = interest_name_val /
                         ParametersSha256DigestComponent(value=params_digest))
    return Interest(value=interest_name / interest_nonce /
                    empty_app_params / interest_sig_info / interest_sig_val)
