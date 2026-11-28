"""Writes a large pcap for the benchmark by repeating a small one.

Usage: python3 bench/big.py <in.pcap> <out.pcap> <megabytes>

Each copy moves the source and destination ports, so every copy is a new set
of flows, and the timestamps keep rising. Only little-endian Ethernet pcap.
"""

import struct
import sys

src, dst, mb = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = open(src, "rb").read()
head, body = data[:24], data[24:]
assert head[:4] == b"\xd4\xc3\xb2\xa1" and struct.unpack("<I", head[20:24])[0] == 1, "little-endian Ethernet pcap only"

packets, i = [], 0
while i < len(body):
    sec, usec, cap, orig = struct.unpack("<IIII", body[i : i + 16])
    packets.append((sec, usec, orig, bytearray(body[i + 16 : i + 16 + cap])))
    i += 16 + cap
span = packets[-1][0] - packets[0][0] + 1


def ports_at(frame):
    """Offset of the TCP or UDP ports in an Ethernet frame, or None."""
    off, kind = 14, struct.unpack(">H", frame[12:14])[0]
    while kind in (0x8100, 0x88A8):
        kind, off = struct.unpack(">H", frame[off + 2 : off + 4])[0], off + 4
    if kind == 0x0800 and frame[off + 9] in (6, 17):
        return off + (frame[off] & 15) * 4
    if kind == 0x86DD and frame[off + 6] in (6, 17):
        return off + 40
    return None


with open(dst, "wb") as out:
    out.write(head)
    size, copy = 24, 0
    while size < mb * 1_000_000:
        for sec, usec, orig, frame in packets:
            f = bytearray(frame)
            at = ports_at(f)
            if at is not None and at + 4 <= len(f):
                sp, dp = struct.unpack(">HH", f[at : at + 4])
                # Move the client side only, so services keep their ports.
                if sp > dp:
                    sp = 1024 + (sp + copy) % 64000
                else:
                    dp = 1024 + (dp + copy) % 64000
                f[at : at + 4] = struct.pack(">HH", sp, dp)
            out.write(struct.pack("<IIII", sec + copy * span, usec, len(f), orig) + f)
            size += 16 + len(f)
        copy += 1
