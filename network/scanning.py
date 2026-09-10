"""Ping-sweeps to populate the ARP cache and guesses OS from TTL; hostnames are resolved on demand elsewhere so scans stay fast."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from network.ip_utils import ip_to_long, long_to_ip
from network.platform_linux import current_device_os_label, get_current_connection, ping_once, read_neighbor_table

# Caps concurrent pings so a /24 sweep finishes in a few rounds instead of one host at a time.
PING_CONCURRENCY = 32
PING_TIMEOUT_MS = 300

# Above this subnet size, sweeping is too slow — fall back to reading the OS's ARP cache instead.
MAX_HOSTS_TO_SWEEP = 512

# No real join-time data exists, so this approximates it: first time this process notices a MAC, in memory only.
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
    """Rough guess from TTL only — Linux, macOS, iOS, and Android all default to 64 so they look identical."""
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

    # Keyed by MAC, not IP: a stale ARP entry can list one device under multiple IPs, and MAC is the identity the rest of the app relies on.
    by_mac: dict[str, dict] = {}
    if connection["mac"]:
        by_mac[connection["mac"]] = {
            "ip": connection["ip"], "hostname": socket.gethostname(),
            "os": current_device_os_label(), "isCurrentDevice": True,
        }
    for entry in arp_entries:
        if entry["mac"] in by_mac:
            continue
        ttl = ttl_by_ip.get(entry["ip"])
        by_mac[entry["mac"]] = {
            "ip": entry["ip"], "hostname": None,
            "os": _guess_os_from_ttl(ttl) if ttl is not None else None,
            "isCurrentDevice": False,
        }

    ranked = sorted(
        ({"mac": mac, **device} for mac, device in by_mac.items()),
        key=lambda d: _track_first_seen(d["mac"]),
        reverse=True,
    )

    return {"localIp": connection["ip"], "subnetMask": connection["subnet"], "devices": ranked}
