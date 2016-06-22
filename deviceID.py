#!/usr/bin/env python3

import base64
import fileinput
import ssl
import sys
from hashlib import sha256


def chunk_str(s, chunk_size):
    return [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]


def luhn_checksum(s):
    a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    factor = 1
    k = 0
    n = len(a)
    for i in s:
        addend = factor * a.index(i)
        factor = 1 if factor == 2 else 2
        addend = (addend // n) + (addend % n)
        k += addend
    remainder = k % n
    checkCodepoint = (n - remainder) % n
    return a[checkCodepoint]


def get_device_id(barray):
    s = "".join([chr(a) for a in base64.b32encode(barray)][:52])
    c = chunk_str(s, 13)
    k = "".join(["%s%s" % (cc, luhn_checksum(cc)) for cc in c])
    return "-".join(chunk_str(k, 7))


def get_device_id_from_string(s):
    s = s.upper()
    s = s.replace("-", "")
    assert(len(s) == 56)
    c = chunk_str(s, 14)
    did = ""
    for cc in c:
        csum = luhn_checksum(cc[0:13])
        if csum != cc[13]:
            return False
        did += cc[0:13]
    did += "===="
    return base64.b32decode(did)


def main():
	if len(sys.argv) != 2:
	    print('usage: {} FILENAME'.format(sys.argv[0]))
	    exit(1)

	with open(sys.argv[1], 'r') as f:
	    v = ssl.PEM_cert_to_DER_cert(f.read())
	    digest = sha256(v).digest()
	    print(get_device_id(digest))

if __name__ == "__main__":
	main()

