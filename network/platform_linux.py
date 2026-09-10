"""Reads live Wi-Fi/Ethernet status via iproute2, iw, and sysfs; runs in a Linux container regardless of host OS, so no Windows code path is needed."""

import logging
import os
import re

from network.ip_utils import cidr_to_mask
from network.shell import normalize_mac, run, run_json

logger = logging.getLogger("network")

WIFI_GENERATION = {
    "802.11be": "Wi-Fi 7",
    "802.11ax": "Wi-Fi 6",
    "802.11ac": "Wi-Fi 5",
    "802.11n": "Wi-Fi 4",
}


def get_protocol_label(radio_type: str | None) -> str | None:
    """"802.11ac" -> "Wi-Fi 5 (802.11ac)"."""
    if not radio_type:
        return None
    generation = WIFI_GENERATION.get(radio_type.lower())
    return f"{generation} ({radio_type})" if generation else radio_type


EMPTY_CONNECTION = {
    "type": None, "connected": False, "interfaceName": None, "networkName": None,
    "bssid": None, "band": None, "channel": None, "radioType": None, "protocol": None,
    "authentication": None, "signalPercent": None, "rssiDbm": None,
    "receiveRateMbps": None, "transmitRateMbps": None, "description": None,
    "manufacturer": None, "driverVersion": None, "ip": None, "subnet": None,
    "gateway": None, "mac": None, "linkLocalIPv6": None, "dnsServers": None,
}


def _get_default_route():
    routes = run_json("ip", ["-j", "route", "show", "default"])
    return routes[0] if routes else None


def _get_addr_info(dev):
    shown = run_json("ip", ["-j", "addr", "show", "dev", dev])
    return shown[0] if shown else None


def _is_wireless_interface(dev: str) -> bool:
    """A `wireless` subdirectory is the kernel's standard way to mark a Wi-Fi interface."""
    return os.path.isdir(f"/sys/class/net/{dev}/wireless")


def _read_sysfs_number(path: str) -> float | None:
    try:
        with open(path) as f:
            value = float(f.read().strip())
        return value if value > 0 else None
    except (OSError, ValueError):
        return None


def _read_sysfs_string(path: str) -> str | None:
    try:
        with open(path) as f:
            value = f.read().strip()
        return value or None
    except OSError:
        return None


def _resolve_dns_servers() -> str | None:
    content = _read_sysfs_string("/etc/resolv.conf")
    if not content:
        return None
    servers = [m.group(1) for line in content.split("\n") if (m := re.match(r"^\s*nameserver\s+(\S+)", line))]
    return ", ".join(servers) if servers else None


def _ip_fields_from_addr(addr, route):
    addr_info = (addr or {}).get("addr_info", [])
    inet = next((a for a in addr_info if a.get("family") == "inet"), None)
    inet6 = next((a for a in addr_info if a.get("family") == "inet6" and a.get("scope") == "link"), None)
    return {
        "ip": (inet or {}).get("local") or route.get("prefsrc"),
        "subnet": cidr_to_mask(inet["prefixlen"]) if inet else None,
        "gateway": route.get("gateway"),
        "linkLocalIPv6": (inet6 or {}).get("local"),
        "dnsServers": _resolve_dns_servers(),
    }


def _freq_to_band_channel(freq_mhz: int):
    """IEEE 802.11 channel + band from a frequency reported in MHz."""
    if freq_mhz == 2484:
        return "2.4 GHz", "14"
    if 2412 <= freq_mhz <= 2472:
        return "2.4 GHz", str(round((freq_mhz - 2407) / 5))
    if 5000 <= freq_mhz < 5900:
        return "5 GHz", str(round((freq_mhz - 5000) / 5))
    if 5925 <= freq_mhz <= 7125:
        return "6 GHz", str(round((freq_mhz - 5950) / 5))
    return f"{freq_mhz / 1000:.1f} GHz", ""


def _rssi_to_percent(rssi_dbm: int) -> float:
    """Same linear approximation NetworkManager uses to turn dBm into a percent (-100dBm -> 0%, -50dBm+ -> 100%)."""
    return max(0.0, min(100.0, 2 * (rssi_dbm + 100)))


def _radio_type_from_bitrate_line(line: str | None) -> str | None:
    """The bitrate line's MCS-scheme prefix is the only place `iw` names the Wi-Fi generation; a bare "MCS" means 802.11n."""
    if not line:
        return None
    if re.search(r"EHT-MCS", line, re.I):
        return "802.11be"
    if re.search(r"HE-MCS", line, re.I):
        return "802.11ax"
    if re.search(r"VHT-MCS", line, re.I):
        return "802.11ac"
    if re.search(r"\bMCS\b", line, re.I):
        return "802.11n"
    return None


def _rate_from_line(line: str | None) -> float | None:
    if not line:
        return None
    m = re.match(r"^([\d.]+)", line)
    return float(m.group(1)) if m else None


def _build_wifi_connection(dev, route, addr):
    link_out = run("iw", ["dev", dev, "link"])
    station_out = run("iw", ["dev", dev, "station", "dump"])

    bssid_match = re.search(r"Connected to ([0-9a-f:]{17})", link_out, re.I)
    ssid_match = re.search(r"SSID:\s*(.+)", link_out)
    freq_match = re.search(r"freq:\s*(\d+)", link_out)
    band, channel = _freq_to_band_channel(int(freq_match.group(1))) if freq_match else (None, None)

    signal_match = re.search(r"^\s*signal:\s*(-?\d+)", station_out, re.M)
    tx_match = re.search(r"^\s*tx bitrate:\s*(.+)$", station_out, re.M)
    rx_match = re.search(r"^\s*rx bitrate:\s*(.+)$", station_out, re.M)
    tx_line = tx_match.group(1) if tx_match else None
    rx_line = rx_match.group(1) if rx_match else None
    rssi_dbm = int(signal_match.group(1)) if signal_match else None
    radio_type = _radio_type_from_bitrate_line(tx_line or rx_line)

    return {
        **EMPTY_CONNECTION,
        "type": "wifi",
        "connected": True,
        "interfaceName": dev,
        "networkName": ssid_match.group(1).strip() if ssid_match else None,
        "bssid": bssid_match.group(1) if bssid_match else None,
        "band": band,
        "channel": channel,
        "radioType": radio_type,
        "protocol": get_protocol_label(radio_type),
        "signalPercent": round(_rssi_to_percent(rssi_dbm)) if rssi_dbm is not None else None,
        "rssiDbm": rssi_dbm,
        "receiveRateMbps": _rate_from_line(rx_line),
        "transmitRateMbps": _rate_from_line(tx_line),
        "mac": normalize_mac((addr or {}).get("address")),
        **_ip_fields_from_addr(addr, route),
    }


def _get_ethtool_driver_info(dev):
    stdout = run("ethtool", ["-i", dev])
    driver_match = re.search(r"^driver:\s*(.+)$", stdout, re.M)
    if not driver_match:
        return None
    version_match = re.search(r"^version:\s*(.+)$", stdout, re.M)
    version = version_match.group(1).strip() if version_match else None
    return {"driver": driver_match.group(1).strip(), "version": version or None}


def _build_ethernet_connection(dev, route, addr):
    speed_mbps = _read_sysfs_number(f"/sys/class/net/{dev}/speed")
    duplex = _read_sysfs_string(f"/sys/class/net/{dev}/duplex")
    driver_info = _get_ethtool_driver_info(dev)

    description = None
    if driver_info:
        description = f"{driver_info['driver']} driver" + (f" ({duplex}-duplex)" if duplex else "")

    return {
        **EMPTY_CONNECTION,
        "type": "ethernet",
        "connected": True,
        "interfaceName": dev,
        "receiveRateMbps": speed_mbps,
        "transmitRateMbps": speed_mbps,
        "description": description,
        "driverVersion": (driver_info or {}).get("version"),
        "mac": normalize_mac((addr or {}).get("address")),
        **_ip_fields_from_addr(addr, route),
    }


def get_current_connection() -> dict:
    route = _get_default_route()
    if not route:
        logger.warning(
            "No default route visible inside the container — if this is a Windows host, "
            "check Docker Desktop's host-networking setting and WSL2 mirrored networking mode."
        )
        return dict(EMPTY_CONNECTION)

    addr = _get_addr_info(route["dev"])
    if _is_wireless_interface(route["dev"]):
        return _build_wifi_connection(route["dev"], route, addr)
    return _build_ethernet_connection(route["dev"], route, addr)


def read_neighbor_table(local_ip: str) -> list[dict]:
    """Entries still resolving or that gave up have no `lladdr` and are skipped."""
    neighbors = run_json("ip", ["-j", "neigh", "show"]) or []
    return [{"ip": n["dst"], "mac": normalize_mac(n["lladdr"])} for n in neighbors if n.get("lladdr")]


def _ping_args(target: str, count: int, timeout_ms: int) -> list[str]:
    """iputils' `-W` is whole seconds, and 0 is rejected by older versions, so round up with a 1s floor."""
    timeout_sec = max(1, -(-timeout_ms // 1000))
    return ["-c", str(count), "-W", str(timeout_sec), target]


def ping_once(ip: str, timeout_ms: int) -> dict:
    stdout = run("ping", _ping_args(ip, 1, timeout_ms))
    match = re.search(r"ttl=(\d+)", stdout, re.I)
    return {"alive": match is not None, "ttl": int(match.group(1)) if match else None}


def measure_packet_loss(target: str, count: int, timeout_ms: int) -> dict | None:
    """Sends `count` pings in one call and parses iputils' summary line; `run()` still returns stdout even though `ping` exits non-zero at 100% loss."""
    stdout = run("ping", _ping_args(target, count, timeout_ms))
    match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received,.*?([\d.]+)% packet loss", stdout, re.I)
    if not match:
        return None
    return {"sent": int(match.group(1)), "received": int(match.group(2)), "lossPercent": float(match.group(3))}


def current_device_os_label() -> str:
    return "Linux"
