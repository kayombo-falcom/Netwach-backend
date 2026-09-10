"""Checks one device's OS on demand by gathering independent signals (nmap, NetBIOS, banners, mDNS, SSDP, ports, TTL, MAC vendor) in parallel and fusing them — no signal decides alone, and `mac` only feeds the OUI vendor hint.
nmap's -sV output rides along as `services` (extra detail, not a fusion signal); every result is "estimated" from remote fingerprinting, never a "verified" self-report."""

import re
import socket

from network.lan_scope import is_ip_in_local_subnet
from network.os_signals import (
    collect_banner_signals, collect_mdns_signals, collect_netbios_signal,
    collect_oui_signal, collect_ssdp_signal, port_signals, ttl_signal,
)
from network.platform_linux import ping_once
from network.shell import run_ok, run_parallel, run_result

REACHABILITY_TIMEOUT_S = 0.5
REACHABILITY_TIMEOUT_MS = int(REACHABILITY_TIMEOUT_S * 1000)
NMAP_TIMEOUT_S = 30

# A firewalled device (Windows default, many phones) drops ICMP but still answers TCP — even a refusal proves it's alive.
TCP_PROBE_PORTS = [80, 443, 445, 139, 3389, 22, 8080]
TCP_PROBE_TIMEOUT_S = 0.4

# A winning family needs at least this much total weight — one weak signal alone isn't enough to call it.
MIN_TOTAL_WEIGHT = 3
# ...and needs to clearly lead the runner-up, not just edge it out, or the result is too ambiguous to report.
MIN_MARGIN_RATIO = 1.5

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _parse_attributes(tag: str) -> dict:
    return dict(re.findall(r'(\w+)="([^"]*)"', tag))


def _parse_best_os_match(xml: str) -> dict | None:
    """Picks nmap's highest-accuracy <osmatch>, paired with its nested <osclass> (family/version/device type)."""
    best = None
    for match in re.finditer(r"<osmatch\s+([^>]*?)/?>([\s\S]*?)(?:</osmatch>|$)", xml):
        attrs = _parse_attributes(match.group(1))
        if "name" not in attrs or "accuracy" not in attrs:
            continue
        try:
            accuracy = float(attrs["accuracy"])
        except ValueError:
            continue

        osclass_match = re.search(r"<osclass\s+([^>]*?)/?>", match.group(2))
        osclass_attrs = _parse_attributes(osclass_match.group(1)) if osclass_match else {}

        candidate = {
            "name": attrs["name"], "accuracy": accuracy,
            "deviceType": osclass_attrs.get("type"),
            "osFamily": osclass_attrs.get("osfamily"),
            "osVersion": osclass_attrs.get("osgen"),
        }
        if best is None or candidate["accuracy"] > best["accuracy"]:
            best = candidate
    return best


def _host_is_up(xml: str) -> bool:
    return bool(re.search(r'<status\s+state="up"', xml, re.I))


def _parse_open_services(xml: str) -> list[dict]:
    """Every open port -sV fingerprinted; closed/filtered ports are skipped since nmap already summarizes those as a count."""
    services = []
    for port_match in re.finditer(r"<port\s+([^>]*)>([\s\S]*?)</port>", xml):
        port_attrs = _parse_attributes(port_match.group(1))
        body = port_match.group(2)

        state_match = re.search(r"<state\s+([^>]*)/?>", body)
        state_attrs = _parse_attributes(state_match.group(1)) if state_match else {}
        if state_attrs.get("state") != "open":
            continue

        try:
            port = int(port_attrs.get("portid", ""))
        except ValueError:
            continue

        service_match = re.search(r"<service\s+([^>]*)/?>", body)
        service_attrs = _parse_attributes(service_match.group(1)) if service_match else {}

        services.append({
            "port": port,
            "protocol": port_attrs.get("protocol"),
            "service": service_attrs.get("name"),
            "product": service_attrs.get("product"),
            "version": service_attrs.get("version"),
            "extraInfo": service_attrs.get("extrainfo"),
        })
    services.sort(key=lambda s: s["port"])
    return services


def _is_nmap_available() -> bool:
    return run_ok("nmap", ["--version"]) is not None


def _tcp_probe(ip: str, port: int) -> dict:
    """A refusal proves the host is alive, but not that the port is open — only a real connect does."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TCP_PROBE_TIMEOUT_S)
        sock.connect((ip, port))
        return {"alive": True, "open": True}
    except ConnectionRefusedError:
        return {"alive": True, "open": False}
    except OSError:
        return {"alive": False, "open": False}
    finally:
        sock.close()


def _check_reachability(ip: str) -> dict:
    """Runs ICMP and TCP probes together, since open ports are themselves a signal; two pings so one dropped packet doesn't mark a live device unreachable."""
    ping1, ping2, *tcp_results = run_parallel(
        lambda: ping_once(ip, REACHABILITY_TIMEOUT_MS),
        lambda: ping_once(ip, REACHABILITY_TIMEOUT_MS),
        *(lambda p=port: _tcp_probe(ip, p) for port in TCP_PROBE_PORTS),
    )
    ping = ping1 if ping1["alive"] else ping2
    open_ports = [port for port, r in zip(TCP_PROBE_PORTS, tcp_results) if r["open"]]
    tcp_alive = any(r["alive"] for r in tcp_results)
    return {"alive": ping["alive"] or tcp_alive, "ttl": ping["ttl"], "openPorts": open_ports}


def _run_nmap(ip: str) -> dict:
    """-Pn skips nmap's own ping (already checked); --max-os-tries/--osscan-guess try harder since nmap is just one vote now; --top-ports 100 -T4 keep it fast; -sV fingerprints those same ports; --host-timeout avoids us killing it.
    Needs CAP_NET_RAW/CAP_NET_ADMIN (granted in docker-compose.yml) for -O's raw-packet fingerprinting."""
    if not _is_nmap_available():
        return {"status": "unavailable"}

    result = run_result(
        "nmap",
        ["-O", "-sV", "-Pn", "-T4", "--top-ports", "100", "--host-timeout", "20s",
         "--max-os-tries", "2", "--osscan-guess", "-oX", "-", ip],
        timeout=NMAP_TIMEOUT_S,
    )
    if result is None:
        return {"status": "error", "reason": "Scan timed out"}

    if result.returncode != 0:
        combined = (result.stdout or "") + (result.stderr or "")
        if "root privileges" in combined:
            return {"status": "error", "reason": "OS detection requires administrator privileges"}
        return {"status": "error", "reason": "Scan failed"}
    return {"status": "ok", "xml": result.stdout}


def _normalize_family(raw: str) -> str | None:
    """Maps nmap's free-text OS name to canonical buckets; device types like router/printer get no vote."""
    lower = raw.lower()
    if "windows" in lower:
        return "Windows"
    if "mac os" in lower or lower == "macos":
        return "macOS"
    if "ios" in lower:
        return "iOS"
    if "android" in lower:
        return "Android"
    if "linux" in lower:
        return "Linux"
    return None


def _fuse_signals(signals: list[dict]) -> dict | None:
    """Sums each family's weight; the winner needs a minimum total and a clear lead over the runner-up, so agreement decides, not one engine's confidence."""
    totals: dict[str, float] = {}
    for signal in signals:
        totals[signal["family"]] = totals.get(signal["family"], 0) + signal["weight"]

    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    if not ranked:
        return None

    top_family, top_weight = ranked[0]
    runner_up_weight = ranked[1][1] if len(ranked) > 1 else 0
    if top_weight < MIN_TOTAL_WEIGHT:
        return None
    if runner_up_weight > 0 and top_weight < runner_up_weight * MIN_MARGIN_RATIO:
        return None

    total_weight = sum(s["weight"] for s in signals)
    return {"family": top_family, "confidence": round((top_weight / total_weight) * 100)}


def _to_signal_details(signals: list[dict], only_family: str | None = None) -> list[dict]:
    """Sorted strongest-first so the most authoritative evidence surfaces up top."""
    filtered = [s for s in signals if only_family is None or s["family"] == only_family]
    filtered.sort(key=lambda s: s["weight"], reverse=True)
    return [{"source": s["source"], "detail": s["detail"]} for s in filtered]


def detect_os(ip: str, mac: str | None = None) -> dict:
    if not IPV4_PATTERN.match(ip):
        return {"status": "engine_unavailable", "reason": "Invalid IPv4 address"}

    if not is_ip_in_local_subnet(ip):
        return {"status": "out_of_scope"}

    reachability = _check_reachability(ip)
    if not reachability["alive"]:
        return {"status": "unreachable"}

    nmap_run, netbios_signal, banner_signals, mdns_signals, ssdp_signals = run_parallel(
        lambda: _run_nmap(ip),
        lambda: collect_netbios_signal(ip),
        lambda: collect_banner_signals(ip),
        lambda: collect_mdns_signals(ip),
        lambda: collect_ssdp_signal(ip),
    )

    signals = [*banner_signals, *mdns_signals, *ssdp_signals, *port_signals(reachability["openPorts"])]
    if netbios_signal:
        signals.append(netbios_signal)
    if ttl := ttl_signal(reachability["ttl"]):
        signals.append(ttl)
    if oui := collect_oui_signal(mac):
        signals.append(oui)

    nmap_match = None
    services: list[dict] = []
    if nmap_run["status"] == "ok" and _host_is_up(nmap_run["xml"]):
        nmap_match = _parse_best_os_match(nmap_run["xml"])
        services = _parse_open_services(nmap_run["xml"])
        if nmap_match:
            family = _normalize_family(nmap_match["osFamily"] or nmap_match["name"])
            if family:
                signals.append({"source": "nmap", "family": family, "detail": nmap_match["name"], "weight": nmap_match["accuracy"] / 20})

    fused = _fuse_signals(signals)
    if fused:
        nmap_agrees = bool(nmap_match) and _normalize_family(nmap_match["osFamily"] or nmap_match["name"]) == fused["family"]
        return {
            "status": "detected",
            "method": "estimated",
            "osFamily": fused["family"],
            "osName": nmap_match["name"] if nmap_agrees else fused["family"],
            "osVersion": nmap_match["osVersion"] if nmap_agrees else None,
            "deviceType": nmap_match["deviceType"] if nmap_agrees else None,
            "confidence": fused["confidence"],
            "signals": _to_signal_details(signals, fused["family"]),
            "services": services,
        }

    # Only fail outright if nothing came back at all — a device with just a NetBIOS/mDNS reply should still show "unknown".
    if not signals and nmap_run["status"] != "ok":
        reason = nmap_run["reason"] if nmap_run["status"] == "error" else "OS detection engine is not available on this host"
        return {"status": "engine_unavailable", "reason": reason}

    return {
        "status": "unknown",
        "method": "estimated",
        "confidence": nmap_match["accuracy"] if nmap_match else None,
        "signals": _to_signal_details(signals),
        "services": services,
    }
