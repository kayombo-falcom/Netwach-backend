"""mDNS (Bonjour) — multicast question + matching answer within a timeout; one socket per lookup since each Django request is its own lookup."""

import socket

from network.dns_wire import TYPE_PTR, TYPE_TXT, build_query, parse_message
from network.udp import CONTINUE, recv_until

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


def _query_until(name: str, qtype: int, timeout_s: float, extract):
    """Sends one mDNS question and returns extract(message) for the first response where that isn't None, or None after timeout_s."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("0.0.0.0", MDNS_PORT))
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)

        sock.sendto(build_query([(name, qtype)]), (MDNS_ADDR, MDNS_PORT))

        def on_packet(data: bytes, _addr):
            result = extract(parse_message(data))
            return result if result is not None else CONTINUE

        return recv_until(sock, timeout_s, on_packet)
    except OSError:
        return None
    finally:
        sock.close()


def resolve_ptr(ptr_name: str, timeout_s: float) -> str | None:
    """Reverse-PTR lookup — the main way Apple devices (and increasingly Android/IoT) announce a name over mDNS."""

    def extract(message):
        for answer in message["answers"]:
            if answer["type"] == TYPE_PTR and answer["name"] == ptr_name:
                return str(answer["data"]).rstrip(".")
        return None

    return _query_until(ptr_name, TYPE_PTR, timeout_s, extract)


def query_service_for_ip(service_type: str, ip: str, timeout_s: float) -> dict:
    """Asks for `service_type`, matching a reply to `ip` via its A record so one query both confirms the service and reads its TXT `model=`; matching within a single packet avoids mixing one device's A with another's TXT."""

    def extract(message):
        additionals = message["additionals"]
        if not any(a["type"] == 1 and a["data"] == ip for a in additionals):
            return None
        txt = next((a for a in additionals if a["type"] == TYPE_TXT), None)
        model = None
        if txt:
            for entry in txt["data"]:
                if entry.startswith("model="):
                    model = entry[len("model="):]
                    break
        return {"present": True, "model": model}

    result = _query_until(service_type, TYPE_PTR, timeout_s, extract)
    return result or {"present": False, "model": None}
