#! /usr/bin/env python
# -*- encoding: utf-8 -*-

"""
Ya, don't know why I'm doing this. Just thought it would be fun to reverse my
old public PGP key.
"""

import base64
import sys

def bruteforce(filename, version, data):
    pass

def parse(file):
    data = []
    parsing = False
    version = None
    version_field = "Version: "
    for line in file.read().split("\n"):
        if line.startswith("-----BEGIN PGP MESSAGE-----"):
            parsing = True
        elif parsing:
            if line.startswith(version_field):
                version = line[len(version_field):]
            elif line.startswith("-----END PGP MESSAGE-----"):
                break
            elif len(line.strip()) > 0:
                data.append(line.strip())
    return file.name, version, base64.decodestring("".join(data))

def decode(filename, version, data):
    print("Filename: %s" % filename)
    print("Version: %s" % version)
    print("Bytes: %d" % len(data))

    raw = map(ord, data)
    ptag = int(raw[0])
    print("PTag raw: 0x%x" % ptag)
    assert (ptag & 0x80) == 0x80, "Incorrect PTag"
    print("PTag header OK")
    assert (ptag & 0x40) == 0, "Unsupported packet format"
    print("Old format OK")

    tag = (ptag & 0x3c) >> 2
    print("PTag: 0x%x" % tag)

    ltype = (ptag & 0x03)
    print("Length-type raw: 0x%x" % ltype)
    plen, hlen = {0: (1,2), 1: (2,3), 3: (-1, 1)}.get(ltype)
    print("Packet has a %d-octet length" % plen)
    print("The header is %d-octet%s long" % (hlen, "s" if hlen==0 else ""))

    assert ltype == 0, "Unsupported packet lengh-type"

    return filename, version, data


if __name__ == "__main__":
    for file in sys.argv[1:]:
        with open(file, "rt") as f:
            bruteforce(*decode(*parse(f)))
