"""Independent OS-fingerprinting signals (banners, mDNS, SSDP, NetBIOS, MAC vendor); nmap's own vote lives in os_fingerprint.py. Each signal has a `family`, `detail`, and `weight` for fusion there."""

import re
import socket

from network.mdns_client import query_service_for_ip
from network.netbios import query_netbios_name
from network.shell import run_parallel
from network.ssdp import query_ssdp

NETBIOS_PRESENCE_TIMEOUT_S = 0.4
BANNER_TIMEOUT_S = 0.8
BANNER_MAX_BYTES = 512
MDNS_ENRICH_TIMEOUT_S = 0.6
SSDP_TIMEOUT_S = 1.5

LINUX_DISTRO_PATTERN = re.compile(r"(Ubuntu|Debian|Raspbian|CentOS|Fedora|Alpine|openSUSE)", re.I)

# A MAC vendor only counts as a signal when it makes single-purpose hardware for one OS — kept small and correct rather than broad and half-wrong.
OUI_FAMILY_HINTS = {
    "b8:27:eb": {"vendor": "Raspberry Pi Foundation", "family": "Linux"},
    "dc:a6:32": {"vendor": "Raspberry Pi Foundation", "family": "Linux"},
    "e4:5f:01": {"vendor": "Raspberry Pi Foundation", "family": "Linux"},
}


def collect_netbios_signal(ip: str) -> dict | None:
    """Answering NBNS at all almost always means Windows (rarely Samba on Linux)."""
    name = query_netbios_name(ip, NETBIOS_PRESENCE_TIMEOUT_S)
    if not name:
        return None
    return {"source": "netbios", "family": "Windows", "detail": f'Responded to NetBIOS name service as "{name}"', "weight": 3}


def collect_oui_signal(mac: str | None) -> dict | None:
    """MAC vendor as a weak OS hint — only for vendors whose hardware only ever runs one OS."""
    if not mac:
        return None
    hint = OUI_FAMILY_HINTS.get(mac.lower()[:8])
    if not hint:
        return None
    return {"source": "oui", "family": hint["family"], "detail": f"MAC vendor: {hint['vendor']}", "weight": 2}


def _grab_banner(ip: str, port: int, probe: str | None = None) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data = b""
    try:
        sock.settimeout(BANNER_TIMEOUT_S)
        sock.connect((ip, port))
        if probe:
            sock.sendall(probe.encode("utf8"))
        while len(data) < BANNER_MAX_BYTES:
            chunk = sock.recv(BANNER_MAX_BYTES)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    finally:
        sock.close()
    return data.decode("utf8", errors="replace") or None


def _classify_ssh_banner(banner: str) -> dict | None:
    """SSH sends its banner unprompted (RFC 4253); only a distro-tagged banner is unambiguous enough to vote on."""
    match = LINUX_DISTRO_PATTERN.search(banner)
    if not match:
        return None
    return {"source": "ssh-banner", "family": "Linux", "detail": f"SSH banner names {match.group(1)}", "weight": 4}


def _classify_http_banner(banner: str) -> dict | None:
    """HTTP `Server:` header — only voted on when it names an OS/distro explicitly, since a bare "nginx"/"Apache" runs anywhere."""
    match = re.search(r"^Server:\s*(.+)$", banner, re.I | re.M)
    if not match:
        return None
    server = match.group(1).strip()
    if re.search(r"Microsoft-IIS", server, re.I):
        return {"source": "http-banner", "family": "Windows", "detail": f"Server header: {server}", "weight": 3}
    distro = LINUX_DISTRO_PATTERN.search(server)
    if distro:
        return {"source": "http-banner", "family": "Linux", "detail": f"Server header: {server}", "weight": 3}
    return None


def collect_banner_signals(ip: str) -> list[dict]:
    """SSH (22) and HTTP's `Server:` header (80) — the two ports that hand back a plain-text banner with no protocol negotiation."""
    ssh_banner, http_banner = run_parallel(
        lambda: _grab_banner(ip, 22),
        lambda: _grab_banner(ip, 80, f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"),
    )
    signals = []
    if ssh_banner and (s := _classify_ssh_banner(ssh_banner)):
        signals.append(s)
    if http_banner and (s := _classify_http_banner(http_banner)):
        signals.append(s)
    return signals


def _classify_ssdp_server(server: str) -> dict | None:
    """SSDP's `SERVER:` header is more standardized than HTTP's, so it's trusted for Android/macOS too."""
    if re.search(r"android", server, re.I):
        return {"source": "ssdp-server", "family": "Android", "detail": f"SSDP SERVER header: {server}", "weight": 3}
    if re.search(r"windows", server, re.I):
        return {"source": "ssdp-server", "family": "Windows", "detail": f"SSDP SERVER header: {server}", "weight": 3}
    if re.search(r"mac os|darwin", server, re.I):
        return {"source": "ssdp-server", "family": "macOS", "detail": f"SSDP SERVER header: {server}", "weight": 3}
    distro = LINUX_DISTRO_PATTERN.search(server)
    if distro:
        return {"source": "ssdp-server", "family": "Linux", "detail": f"SSDP SERVER header names {distro.group(1)}", "weight": 3}
    return None


def collect_ssdp_signal(ip: str) -> list[dict]:
    """SSDP (UPnP) M-SEARCH — answered by some Android phones and most smart-TV/IoT devices even when mDNS is silent."""
    response = query_ssdp(ip, SSDP_TIMEOUT_S)
    server = (response or {}).get("headers", {}).get("SERVER")
    if not server:
        return []
    signal = _classify_ssdp_server(server)
    return [signal] if signal else []


def _family_from_apple_model(model: str) -> str:
    return "iOS" if re.match(r"^(iPhone|iPad|iPod)", model) else "macOS"


def collect_mdns_signals(ip: str) -> list[dict]:
    """mDNS/Bonjour enrichment: `_device-info._tcp` gives an Apple device's real model, the strongest non-nmap signal; `_smb`/`_googlecast` are weak hints only."""
    device_info, smb, cast = run_parallel(
        lambda: query_service_for_ip("_device-info._tcp.local", ip, MDNS_ENRICH_TIMEOUT_S),
        lambda: query_service_for_ip("_smb._tcp.local", ip, MDNS_ENRICH_TIMEOUT_S),
        lambda: query_service_for_ip("_googlecast._tcp.local", ip, MDNS_ENRICH_TIMEOUT_S),
    )

    signals = []
    if device_info["present"]:
        family = _family_from_apple_model(device_info["model"]) if device_info["model"] else "macOS"
        signals.append({
            "source": "mdns-device-info", "family": family,
            "detail": device_info["model"] or "Advertises Apple device-info service",
            "weight": 5 if device_info["model"] else 3,
        })
    if smb["present"]:
        signals.append({"source": "mdns-smb", "family": "Windows", "detail": "Advertises SMB file sharing", "weight": 1})
    if cast["present"]:
        signals.append({"source": "mdns-googlecast", "family": "Android", "detail": "Advertises Google Cast", "weight": 1})
    return signals


def ttl_signal(ttl: int | None) -> dict | None:
    """Weakest fallback signal — skipped when ambiguous, since 64-or-under TTL is shared by Linux, macOS, and Android."""
    if ttl is None:
        return None
    if ttl > 128:
        return {"source": "ttl", "family": "Network device", "detail": f"Ping TTL {ttl}", "weight": 0.5}
    if ttl > 64:
        return {"source": "ttl", "family": "Windows", "detail": f"Ping TTL {ttl}", "weight": 0.5}
    return None


def port_signals(open_ports: list[int]) -> list[dict]:
    """Open liveness ports are weak OS evidence too — RDP in particular is close to Windows-exclusive by default."""
    signals = []
    if 3389 in open_ports:
        signals.append({"source": "port-3389", "family": "Windows", "detail": "RDP port open", "weight": 2})
    if 445 in open_ports and 139 in open_ports:
        signals.append({"source": "port-smb", "family": "Windows", "detail": "SMB ports 445+139 open", "weight": 1})
    return signals
