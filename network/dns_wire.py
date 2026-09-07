"""Minimal DNS wire-format encode/decode — just enough (A/PTR/TXT, name
compression) for mDNS questions and responses. Hand-rolled instead of adding
a dependency, matching the raw-socket approach netbios.py/ssdp.py already use."""

import struct

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Returns (name, offset_after_name), following compression pointers
    (RFC 1035 §4.1.4) without looping back through them for the return offset."""
    labels = []
    pos = offset
    jumped = False
    end_offset = offset
    visited: set[int] = set()

    while pos < len(buf):
        if pos in visited:
            break  # guard against a malformed/malicious pointer loop
        visited.add(pos)

        length = buf[pos]
        if length == 0:
            if not jumped:
                end_offset = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(buf):
                break
            pointer = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end_offset = pos + 2
            jumped = True
            pos = pointer
            continue
        pos += 1
        labels.append(buf[pos:pos + length].decode("ascii", errors="replace"))
        pos += length

    return ".".join(labels), end_offset


def build_query(questions: list[tuple[str, int]], transaction_id: int = 0) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0, len(questions), 0, 0, 0)
    body = b"".join(encode_name(name) + struct.pack(">HH", qtype, 1) for name, qtype in questions)
    return header + body


def parse_question(buf: bytes) -> tuple[str, int] | None:
    """The first question's (name, qtype) from a DNS message — for reading a
    client's outbound query, unlike parse_message() below which reads a
    server's answers. None if the buffer is too short or truncated mid-name."""
    if len(buf) < 12:
        return None

    _tid, _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(">HHHHHH", buf[:12])
    if qdcount < 1:
        return None

    name, offset = decode_name(buf, 12)
    if offset + 4 > len(buf):
        return None
    qtype, _qclass = struct.unpack(">HH", buf[offset:offset + 4])
    return name, qtype


def parse_message(buf: bytes) -> dict:
    """Returns {"answers": [...], "additionals": [...]} — each record a dict
    with name/type/data (rdata decoded for A/PTR/TXT, raw bytes otherwise)."""
    if len(buf) < 12:
        return {"answers": [], "additionals": []}

    _tid, _flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", buf[:12])
    offset = 12

    for _ in range(qdcount):
        _name, offset = decode_name(buf, offset)
        offset += 4  # qtype + qclass

    def parse_records(count, offset):
        records = []
        for _ in range(count):
            name, offset = decode_name(buf, offset)
            if offset + 10 > len(buf):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", buf[offset:offset + 10])
            offset += 10
            rdata_raw = buf[offset:offset + rdlength]
            data: object = rdata_raw

            if rtype == TYPE_A and len(rdata_raw) == 4:
                data = ".".join(str(b) for b in rdata_raw)
            elif rtype == TYPE_PTR:
                data, _ = decode_name(buf, offset)
            elif rtype == TYPE_TXT:
                entries = []
                pos = 0
                while pos < len(rdata_raw):
                    length = rdata_raw[pos]
                    entries.append(rdata_raw[pos + 1:pos + 1 + length].decode("utf8", errors="replace"))
                    pos += 1 + length
                data = entries

            records.append({"name": name, "type": rtype, "data": data})
            offset += rdlength
        return records, offset

    answers, offset = parse_records(ancount, offset)
    for _ in range(nscount):
        _name, offset = decode_name(buf, offset)
        if offset + 10 > len(buf):
            break
        _rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", buf[offset:offset + 10])
        offset += 10 + rdlength
    additionals, _offset = parse_records(arcount, offset)

    return {"answers": answers, "additionals": additionals}
