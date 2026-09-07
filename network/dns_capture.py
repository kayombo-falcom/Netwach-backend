"""Passively captures DNS queries crossing this host's LAN-facing interface
and turns them into DeviceActivity rows, one per device per query.

This host is the LAN's router — every device's outbound DNS query already
transits it pre-NAT, so a raw socket bound to that interface sees it without
needing to be in anyone's traffic path deliberately (no ARP spoofing). A
captured frame's own Ethernet source MAC is the querying device's real MAC:
since the device is one L2 hop away, there's no ARP-cache staleness to worry
about the way an IP-keyed lookup would have.

Hand-rolled instead of adding scapy or shelling out to Zeek, matching the
rest of network/ (see dns_wire.py's own rationale) — this is the first
promiscuous-capture socket in the app; everything else here sends a query
and waits for a unicast reply.

Scope: UDP DNS only. DNS-over-TCP, DoH, DoT, and any query sent over IPv6
transport are all invisible to this technique — permanent limitations of
passive IPv4/UDP capture, not bugs to fix later.
"""

import socket
import struct
from typing import Callable

from django.conf import settings
from django.db import close_old_connections
from django.db import Error as DjangoDatabaseError

from network.dns_wire import parse_question
from network.platform_linux import get_current_connection

DNS_PORT = 53
ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
IPPROTO_UDP = 17


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _parse_ethernet(frame: bytes) -> str | None:
    """The frame's source MAC, or None if too short to have one."""
    if len(frame) < ETH_HEADER_LEN:
        return None
    return _format_mac(frame[6:12])


def _parse_ipv4_header(frame: bytes, offset: int) -> tuple[int, int] | None:
    """(protocol, header_length_bytes), or None if too short/malformed."""
    if offset + 20 > len(frame):
        return None
    version_ihl = frame[offset]
    if (version_ihl >> 4) != 4:
        return None
    ihl_bytes = (version_ihl & 0x0F) * 4
    if ihl_bytes < 20 or offset + ihl_bytes > len(frame):
        return None
    protocol = frame[offset + 9]
    return protocol, ihl_bytes


def _parse_udp_dst_port(frame: bytes, offset: int) -> int | None:
    if offset + 8 > len(frame):
        return None
    _src_port, dst_port = struct.unpack(">HH", frame[offset:offset + 4])
    return dst_port


def _parse_dns_query_frame(frame: bytes) -> tuple[str, str] | None:
    """(src_mac, domain) for a UDP/port-53 DNS query frame, else None."""
    src_mac = _parse_ethernet(frame)
    if src_mac is None:
        return None

    ip_offset = ETH_HEADER_LEN
    ip_header = _parse_ipv4_header(frame, ip_offset)
    if ip_header is None:
        return None
    protocol, ihl_bytes = ip_header
    if protocol != IPPROTO_UDP:
        return None

    udp_offset = ip_offset + ihl_bytes
    dst_port = _parse_udp_dst_port(frame, udp_offset)
    if dst_port != DNS_PORT:
        return None

    dns_offset = udp_offset + 8
    question = parse_question(frame[dns_offset:])
    if question is None:
        return None
    domain, _qtype = question
    return src_mac, domain


def capture_dns_queries(iface: str, on_query: Callable[[str, str], None]) -> None:
    """Blocks forever reading every frame crossing `iface`, calling
    on_query(mac, domain) for each DNS query. A malformed/unexpected frame is
    skipped, never fatal — only a real socket error propagates."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_IPV4))
    sock.bind((iface, 0))
    try:
        while True:
            frame, _addr = sock.recvfrom(65535)
            try:
                parsed = _parse_dns_query_frame(frame)
            except Exception:
                continue
            if parsed is not None:
                on_query(*parsed)
    finally:
        sock.close()


def run_forever(iface: str | None = None) -> None:
    """Entry point for the capture_dns management command."""
    from devices.services import DeviceService

    if iface is None:
        iface = settings.DNS_CAPTURE_IFACE or get_current_connection()["interfaceName"]
    if not iface:
        raise RuntimeError("No capture interface available — set DNS_CAPTURE_IFACE or connect to a network.")

    def on_query(mac: str, domain: str) -> None:
        try:
            DeviceService().record_dns_query(mac=mac, domain=domain)
        except DjangoDatabaseError:
            # This process never sees Django's usual request_started/
            # request_finished signals, so a connection that drops (DB
            # restart, idle timeout) would otherwise stay broken and fail
            # silently on every query for the rest of this process's life —
            # drop it so the next query lazily opens a fresh one.
            close_old_connections()
        except Exception:
            pass

    capture_dns_queries(iface, on_query)
