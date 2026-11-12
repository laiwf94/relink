#!/usr/bin/env python3
"""A one-record DNS server for the demo: answers TXT queries for one name
with one value over UDP, and NXDOMAIN for anything else, so relink can
verify a custom domain without a real zone.

usage: txt-dns.py PORT NAME VALUE
"""
import socket
import struct
import sys


def read_name(msg, i):
    labels = []
    while msg[i]:
        n = msg[i]
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace").lower())
        i += 1 + n
    return ".".join(labels), i + 1


def answer(msg, name, value):
    qid, _flags, qd = struct.unpack(">HHH", msg[:6])
    if qd != 1:
        return None
    qname, end = read_name(msg, 12)
    qtype, _qclass = struct.unpack(">HH", msg[end:end + 4])
    question = msg[12:end + 4]
    found = qname == name and qtype == 16
    flags = 0x8180 if found else 0x8183  # response, RD+RA; rcode 0 or 3
    header = struct.pack(">HHHHHH", qid, flags, 1, 1 if found else 0, 0, 0)
    if not found:
        return header + question
    text = value.encode()
    rdata = bytes([len(text)]) + text
    record = struct.pack(">HHHIH", 0xC00C, 16, 1, 60, len(rdata)) + rdata
    return header + question + record


def main():
    port, name, value = int(sys.argv[1]), sys.argv[2].lower().rstrip("."), sys.argv[3]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    while True:
        msg, peer = sock.recvfrom(512)
        try:
            reply = answer(msg, name, value)
        except (IndexError, struct.error):
            reply = None
        if reply:
            sock.sendto(reply, peer)


if __name__ == "__main__":
    main()
