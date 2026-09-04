"""SSDP (UPnP discovery) — a multicast query that live devices answer by
naming their OS in the SERVER header. Some Android phones and most
smart-TV/media devices answer this even when mDNS doesn't."""

import socket

from network.udp import CONTINUE, recv_until

SSDP_MULTICAST_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SEARCH_WAIT_SECONDS = 1  # MX header — devices stagger their reply by up to this many seconds


def _parse_ssdp_headers(raw: str) -> dict:
    headers = {}
    for line in raw.split("\r\n")[1:]:
        sep = line.find(":")
        if sep == -1:
            continue
        headers[line[:sep].strip().upper()] = line[sep + 1:].strip()
    return headers


def query_ssdp(ip: str, timeout_s: float) -> dict | None:
    """Sends an SSDP M-SEARCH and returns the first reply from `ip` —
    devices reply directly to us, unlike mDNS's shared multicast replies."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        query = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_MULTICAST_ADDR}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            f"MX: {SEARCH_WAIT_SECONDS}\r\n"
            "ST: ssdp:all\r\n\r\n"
        )
        sock.sendto(query.encode("utf8"), (SSDP_MULTICAST_ADDR, SSDP_PORT))

        def on_packet(data: bytes, addr) -> dict | object:
            if addr[0] != ip:  # multicast reaches every listening device; only our target's reply matters
                return CONTINUE
            return {"headers": _parse_ssdp_headers(data.decode("utf8", errors="replace"))}

        return recv_until(sock, timeout_s, on_packet)
    finally:
        sock.close()
