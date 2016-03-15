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

def parse_ascii_armored_file(file):
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
    data = base64.decodestring("".join(data))
    data = map(ord, data)
    return version, data

class Parser(object):
    def __init__(self, version, data):
        self.file_version = version
        self.contents = {}

        self.tags = {
            0: "Reserved - a packet tag MUST NOT have this value",
            1: "Public-Key Encrypted Session Key Packet",
            2: "Signature Packet",
            3: "Symmetric-Key Encrypted Session Key Packet",
            4: "One-Pass Signature Packet",
            5: "Secret-Key Packet",
            6: "Public-Key Packet",
            7: "Secret-Subkey Packet",
            8: "Compressed Data Packet",
            9: "Symmetrically Encrypted Data Packet",
           10: "Marker Packet",
           11: "Literal Data Packet",
           12: "Trust Packet",
           13: "User ID Packet",
           14: "Public-Subkey Packet",
           17: "User Attribute Packet",
           18: "Sym. Encrypted and Integrity Protected Data Packet",
           19: "Modification Detection Code Packet",
           60: "Private or Experimental Values",
           61: "Private or Experimental Values",
           62: "Private or Experimental Values",
           63: "Private or Experimental Values",
        }

        self.pk_algos = {
            1: "RSA (Encrypt or Sign) [HAC]",
            2: "RSA Encrypt-Only [HAC]",
            3: "RSA Sign-Only [HAC]",
           16: "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]",
           17: "DSA (Digital Signature Algorithm) [FIPS186] [HAC]",
           18: "Reserved for Elliptic Curve",
           19: "Reserved for ECDSA",
           20: "Reserved (formerly Elgamal Encrypt or Sign)",
           21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)",
          100: "Private/Experimental algorithm",
          101: "Private/Experimental algorithm",
          102: "Private/Experimental algorithm",
          103: "Private/Experimental algorithm",
          104: "Private/Experimental algorithm",
          105: "Private/Experimental algorithm",
          106: "Private/Experimental algorithm",
          107: "Private/Experimental algorithm",
          108: "Private/Experimental algorithm",
          109: "Private/Experimental algorithm",
          110: "Private/Experimental algorithm",
        }

        self._parse(version, data)

    def _parse(self, version, data):
        print("Version: %s" % version)
        print("Bytes: %d" % len(data))

        tag, body = self.parse_packet_header(data)
        return self.parse_packet_contents(tag, body)

    def parse_mpi(self, octets):
        bits = (octets[0]<<8) | octets[1]
        print("MPI bits: %d" % bits)

        length = ((bits + 7) // 8)

        number = 0
        for i in range(length):
            number <<= 8
            number += octets[2+i]

        return bits, number

    def parse_packet_header(self, octets):
        if (octets[0] & (1<<7)) != (1<<7):
            raise ValueError("Invalid packet; no leading set bit")

        if (octets[0] & (1<<6)) == (1<<6):
            raise NotImplementedError("New packet format unsupported")

        tag = (octets[0] & 0x3c) >> 2

        if tag == 0:
            raise ValueError("Packet has illegally set reserved bit")

        length_type = (octets[0] & 0x03)

        if length_type == 3:
            raise NotImplementedError("Indeterminate length packets unsupported")

        header_length = {0: 2, 1: 3, 2: 5}[length_type]

        body_length = {
            0: octets[1],
            1: (octets[1]<<8) | octets[2],
            2: (octets[1]<<24) | (octets[2]<<16) | (octets[3]<<8) | octets[4],
        }[length_type]

        print("Header length: %d" % header_length)
        print("Body length: %d" % body_length)

        body = octets[header_length:]
        return tag, body

    def parse_packet_contents(self, tag, octets):
        print("Tag (0x%02x): %s" % (tag, self.tags[tag]))

        if tag == 0:
            raise ValueError("Packet has illegally set reserved bit")

        parsers = {
            1: self.parse_pk_encrypted_session_key_packet,
            2: self.parse_signature_packet
        }

        try:
            parser = parsers[tag]
            return parser(octets)
        except KeyError:
            raise NotImplementedError("Unsupported packet: %s" % self.tags[tag])

    def parse_pk_encrypted_session_key_packet(self, octets):
        version = octets[0]
        print("PK Version: %d" % version)

        if version != 3:
            raise NotImplementedError("Unsupported PK Session Key version %d" %
                    version)

        key_id = octets[1:9]
        self.contents["key_id"] = key_id
        print("PK Key ID: %s" % "".join(map(lambda s: "%02x" %s, key_id)))

        pk_algo = octets[9]
        self.contents["pk_algo"] = pk_algo

        print("PK Algorithm (0x%02x): %s" % (pk_algo, self.pk_algos[pk_algo]))

        if pk_algo != 1:
            raise NotImplementedError("Unsupported public key algorithm: %s" %
                    self.pk_algos[pk_algo])

        encrypted_session_key = octets[10:]
        print("PK Encrypted Session Key Length: %d" %
                len(encrypted_session_key))

        # TODO: Parse algo specifics
        bits, m = self.parse_mpi(encrypted_session_key)
        print("%d-bit value of m (RSA m^e mod n): %d" % (bits, m))

        mpi_length = ((bits + 7) // 8)+2
        rest = encrypted_session_key[mpi_length:]
        print("Remaining data: %d" % len(rest))

        return encrypted_session_key

    def parse_signature_packet(self, tag, octets):
        pass


if __name__ == "__main__":
    for file in sys.argv[1:]:
        with open(file, "rt") as f:
            version, data = parse_ascii_armored_file(f)
            p = Parser(version, data)
