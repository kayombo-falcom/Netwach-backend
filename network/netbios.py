"""NetBIOS Name Service (NBNS), RFC 1002 §4.2 — a direct Node Status query to UDP port 137; only Windows/SMB devices with NetBIOS enabled answer."""

import random
import socket
import struct

from network.udp import CONTINUE, recv_until

NBSTAT_PORT = 137
NBSTAT_QUERY_TYPE = 0x21
UNIQUE_NAME_SUFFIX = 0x00  # the <00> workstation entry is the device's own name
GROUP_NAME_FLAG = 0x8000  # set = a shared group/workgroup name, not a specific device


def _encode_netbios_half_ascii(raw_name: bytes) -> bytes:
    """Encodes a raw 16-byte NetBIOS name into NBNS wire format: 2 ASCII chars per nibble ('A' + nibble)."""
    encoded = bytearray(32)
    for i in range(16):
        encoded[i * 2] = 0x41 + ((raw_name[i] >> 4) & 0x0F)
        encoded[i * 2 + 1] = 0x41 + (raw_name[i] & 0x0F)
    return bytes(encoded)


def _build_nbstat_query() -> tuple[bytes, int]:
    """Builds a Node Status query for the wildcard name ("*" + 15 NUL bytes) — the standard "what names do you have?" query."""
    transaction_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", transaction_id, 0, 1, 0, 0, 0)
    wildcard_name = bytes([0x2A]) + bytes(15)
    question = (
        bytes([32]) + _encode_netbios_half_ascii(wildcard_name) + bytes([0])
        + bytes([0x00, NBSTAT_QUERY_TYPE])
        + bytes([0x00, 0x01])  # QCLASS = IN
    )
    return header + question, transaction_id


def _skip_resource_name(buf: bytes, offset: int) -> int:
    if (buf[offset] & 0xC0) == 0xC0:
        return offset + 2
    while offset < len(buf) and buf[offset] != 0:
        offset += buf[offset] + 1
    return offset + 1


def _parse_nbstat_response(buf: bytes) -> str | None:
    """Picks the device's own <00> UNIQUE name out of a Node Status response's name table."""
    if len(buf) < 12 or struct.unpack(">H", buf[6:8])[0] < 1:  # ANCOUNT
        return None

    offset = _skip_resource_name(buf, 12)
    offset += 2 + 2 + 4  # TYPE, CLASS, TTL
    rdata_start = offset + 2  # + RDLENGTH
    if rdata_start >= len(buf):
        return None
    num_names = buf[rdata_start]

    for i in range(num_names):
        entry = rdata_start + 1 + i * 18
        if entry + 18 > len(buf):
            break
        suffix = buf[entry + 15]
        flags = struct.unpack(">H", buf[entry + 16:entry + 18])[0]
        if suffix == UNIQUE_NAME_SUFFIX and (flags & GROUP_NAME_FLAG) == 0:
            return buf[entry:entry + 15].decode("ascii", errors="replace").strip()
    return None


def query_netbios_name(ip: str, timeout_s: float) -> str | None:
    packet, transaction_id = _build_nbstat_query()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(packet, (ip, NBSTAT_PORT))

        def on_packet(data: bytes, _addr) -> str | None | object:
            if len(data) < 2 or struct.unpack(">H", data[0:2])[0] != transaction_id:
                return CONTINUE
            return _parse_nbstat_response(data)  # matched — stop here even if this parses to None

        return recv_until(sock, timeout_s, on_packet)
    finally:
        sock.close()
