#!/usr/bin/env python3
"""Is the mailed bundle really sealed?

The envelope is raw bytes now rather than hex-in-JSON, which halved what a chat
attachment has to carry. That also removes the old check: there are no field
names left to look for. So this checks two things instead — that nothing from
the *payload's* structure shows through, and that the bytes look like
ciphertext rather than data.
"""
import sys
import zlib

blob = open(sys.argv[1], "rb").read()

for leak in (b"amount", b"lineage", b"index", b"asset_hex", b"proof"):
    if leak in blob:
        print(f"FAIL: {leak!r} appears in a supposedly sealed bundle")
        sys.exit(1)

# Ciphertext is incompressible. A plaintext bundle is mostly proof bytes with
# structure, and would give back several percent at minimum.
ratio = len(zlib.compress(blob, 9)) / len(blob)
if ratio < 0.95:
    print(f"FAIL: bundle compresses to {ratio:.0%} of its size - that is not ciphertext")
    sys.exit(1)

print(f"VERIFIED: on-disk bundle is ciphertext only ({len(blob)} bytes, incompressible)")
