"""Discovers devices on the currently joined network: a ping sweep to
populate the ARP cache and guess OS family from TTL. Hostnames aren't
resolved here — that's an on-demand per-device lookup (hostname_resolve.py)
so a bulk scan stays fast. Returned most-recently-first-seen first."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from network.ip_utils import ip_to_long, long_to_ip
from network.platform_linux import current_device_os_label, get_current_connection, ping_once, read_neighbor_table

# Ping sweeps run one host at a time by default — this caps how many run
# concurrently so a /24 sweep finishes in a handful of rounds instead of one
# host at a time.
PING_CONCURRENCY = 32
PING_TIMEOUT_MS = 300

# Ping-sweeping a subnet bigger than this (a /23 or larger) would take an
# unreasonable amount of time and traffic, so above this size we fall back to
# reading whatever the OS's ARP cache already has instead of actively probing.
MAX_HOSTS_TO_SWEEP = 512

# The OS's ARP table has no join-time info — this is the closest honest
# substitute: the first time this running process ever notices a MAC, in
# memory only. Resets on restart and can't reflect anyone who joined earlier.
_first_seen_at_by_mac: dict[str, float] = {}


def _track_first_seen(mac: str) -> float:
    seen_at = _first_seen_at_by_mac.get(mac)
    if seen_at is not None:
        return seen_at
    now = time.time()
    _first_seen_at_by_mac[mac] = now
    return now


def _compute_host_range(local_ip: str, mask: str) -> list[str]:
    """Every usable host address between the network and broadcast address, or [] if the subnet is too large to sweep."""
    mask_long = ip_to_long(mask)
    network = ip_to_long(local_ip) & mask_long
    broadcast = network | (~mask_long & 0xFFFFFFFF)
    host_count = broadcast - network - 1
    if host_count <= 0 or host_count > MAX_HOSTS_TO_SWEEP:
        return []
    return [long_to_ip(h) for h in range(network + 1, broadcast)]


def _guess_os_from_ttl(ttl: int) -> str:
    """Rough OS family from a ping's TTL: Windows, Linux/macOS/Android, and
    most network gear each start from a different well-known default (128,
    64, 255) that only counts down per hop. Not a fingerprint — Linux,
    macOS, iOS, and Android all default to 64 and are indistinguishable."""
    if ttl > 128:
        return "Network device"
    if ttl > 64:
        return "Windows"
    return "Linux / macOS / Android"


def _ping_host(ip: str) -> int | None:
    """Pings a host so a live device answers and populates the ARP cache, returning the reply's TTL if it answered."""
    return ping_once(ip, PING_TIMEOUT_MS)["ttl"]


def scan_connected_devices() -> dict:
    connection = get_current_connection()
    if not connection["connected"] or not connection["ip"] or not connection["subnet"]:
        return {"localIp": None, "subnetMask": None, "devices": []}

    hosts = _compute_host_range(connection["ip"], connection["subnet"])
    ttl_by_ip: dict[str, int | None] = {}
    if hosts:
        with ThreadPoolExecutor(max_workers=PING_CONCURRENCY) as pool:
            ttl_by_ip = dict(zip(hosts, pool.map(_ping_host, hosts)))

    arp_entries = read_neighbor_table(connection["ip"])

    by_ip: dict[str, dict] = {}
    if connection["mac"]:
        by_ip[connection["ip"]] = {
            "mac": connection["mac"], "hostname": socket.gethostname(),
            "os": current_device_os_label(), "isCurrentDevice": True,
        }
    for entry in arp_entries:
        if entry["ip"] in by_ip:
            continue
        ttl = ttl_by_ip.get(entry["ip"])
        by_ip[entry["ip"]] = {
            "mac": entry["mac"], "hostname": None,
            "os": _guess_os_from_ttl(ttl) if ttl is not None else None,
            "isCurrentDevice": False,
        }

    ranked = sorted(
        ({"ip": ip, **device} for ip, device in by_ip.items()),
        key=lambda d: _track_first_seen(d["mac"]),
        reverse=True,
    )

    return {"localIp": connection["ip"], "subnetMask": connection["subnet"], "devices": ranked}
