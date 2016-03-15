#! /usr/bin/env python
# -*- encoding: utf-8 -*-

import base64

def bruteforce(data):
    print("Data: %s" % data)

if __name__ == "__main__":
    for file in sys.argv[1:]:
        with open(file, "rt") as f:
            data = base64.decodestring(f.read())
            bruteforce(data)
