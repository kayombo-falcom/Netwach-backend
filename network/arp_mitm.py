"""Poisons ARP caches to redirect known LAN devices' traffic through this host, so dns_capture.py can see their DNS queries (which passive capture alone can't reach).
Hand-rolled over a raw socket, no scapy, matching the rest of network/.
SAFETY: can disrupt LAN connectivity if misconfigured. Off by default (ARP_MITM_ENABLED); only targets known devices and continuously re-poisons, so stopping the process lets every victim's ARP cache safely revert on its own."""

import signal
import socket
import struct
import time

from django.conf import settings

from network.platform_linux import get_current_connection, read_neighbor_table
from network.shell import normalize_mac

ETHERTYPE_ARP = 0x0806
ARP_HTYPE_ETHERNET = 1
ARP_PTYPE_IPV4 = 0x0800
ARP_HLEN = 6
ARP_PLEN = 4
ARP_OP_REPLY = 2

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def _mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def build_arp_reply(
    *, src_mac: bytes, dst_mac: bytes, sender_ip: str, sender_mac: bytes, target_ip: str, target_mac: bytes,
) -> bytes:
    """One unsolicited ARP reply telling `target_mac`/`target_ip` that `sender_ip` is at `sender_mac` (the lie); `src_mac`/`dst_mac` are just the frame's real Ethernet addressing."""
    ethernet = dst_mac + src_mac + struct.pack(">H", ETHERTYPE_ARP)
    arp = (
        struct.pack(">HHBBH", ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4, ARP_HLEN, ARP_PLEN, ARP_OP_REPLY)
        + sender_mac + socket.inet_aton(sender_ip)
        + target_mac + socket.inet_aton(target_ip)
    )
    return ethernet + arp


def _get_ip_forward() -> str:
    with open(IP_FORWARD_PATH) as f:
        return f.read().strip()


def _set_ip_forward(value: str) -> None:
    with open(IP_FORWARD_PATH, "w") as f:
        f.write(value)


def _resolve_targets(gateway_ip: str) -> tuple[dict | None, list[dict]]:
    """(gateway {ip, mac}, [devices {ip, mac}, ...]) for known NetworkDevice rows with a resolvable MAC in the live ARP table; anything else is silently excluded, not guessed."""
    from devices.services import DeviceService

    neighbor_mac_by_ip = {n["ip"]: n["mac"] for n in read_neighbor_table(gateway_ip)}

    gateway_mac = neighbor_mac_by_ip.get(gateway_ip)
    gateway = {"ip": gateway_ip, "mac": gateway_mac} if gateway_mac else None

    devices = []
    for device in DeviceService().list_devices():
        if not device.ip:
            continue
        mac = neighbor_mac_by_ip.get(device.ip)
        if mac and normalize_mac(mac) == device.mac:
            devices.append({"ip": device.ip, "mac": mac})
    return gateway, devices


def _poison_once(sock: socket.socket, this_mac: bytes, gateway: dict, targets: list[dict]) -> None:
    gateway_mac = _mac_to_bytes(gateway["mac"])
    for target in targets:
        target_mac = _mac_to_bytes(target["mac"])
        # Tell the device the gateway is us.
        sock.send(build_arp_reply(
            src_mac=this_mac, dst_mac=target_mac,
            sender_ip=gateway["ip"], sender_mac=this_mac,
            target_ip=target["ip"], target_mac=target_mac,
        ))
        # Tell the gateway the device is us.
        sock.send(build_arp_reply(
            src_mac=this_mac, dst_mac=gateway_mac,
            sender_ip=target["ip"], sender_mac=this_mac,
            target_ip=gateway["ip"], target_mac=gateway_mac,
        ))


def _unspoof(sock: socket.socket, this_mac: bytes, gateway: dict, targets: list[dict]) -> None:
    """One pass of truthful ARP replies that reverses the poison immediately instead of waiting for cache expiry; framed from this host's own MAC (like _poison_once) so switches' MAC tables aren't confused during recovery."""
    gateway_mac = _mac_to_bytes(gateway["mac"])
    for target in targets:
        target_mac = _mac_to_bytes(target["mac"])
        sock.send(build_arp_reply(
            src_mac=this_mac, dst_mac=target_mac,
            sender_ip=gateway["ip"], sender_mac=gateway_mac,
            target_ip=target["ip"], target_mac=target_mac,
        ))
        sock.send(build_arp_reply(
            src_mac=this_mac, dst_mac=gateway_mac,
            sender_ip=target["ip"], sender_mac=target_mac,
            target_ip=gateway["ip"], target_mac=gateway_mac,
        ))


def run_forever(iface: str | None = None) -> None:
    """Entry point for the arp_mitm management command."""
    if not settings.ARP_MITM_ENABLED:
        print("ARP_MITM_ENABLED is not set — refusing to start. This feature can disrupt every "
              "device's connectivity on the LAN if misconfigured; it must be explicitly opted into.")
        return

    connection = get_current_connection()
    if iface is None:
        iface = settings.DNS_CAPTURE_IFACE or connection["interfaceName"]
    gateway_ip = connection["gateway"]
    this_mac = _mac_to_bytes(connection["mac"]) if connection["mac"] else None
    if not iface or not gateway_ip or not this_mac:
        raise RuntimeError("No capture interface, gateway, or MAC available — connect to a network first.")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_ARP))
    sock.bind((iface, 0))

    original_ip_forward = _get_ip_forward()
    _set_ip_forward("1")

    state = {"gateway": None, "targets": [], "running": True}

    def _shutdown(signum, frame):
        state["running"] = False

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while state["running"]:
            gateway, targets = _resolve_targets(gateway_ip)
            if gateway and targets:
                state["gateway"], state["targets"] = gateway, targets
                _poison_once(sock, this_mac, gateway, targets)
            time.sleep(settings.ARP_MITM_INTERVAL_SECONDS)
    finally:
        if state["gateway"] and state["targets"]:
            _unspoof(sock, this_mac, state["gateway"], state["targets"])
        _set_ip_forward(original_ip_forward)
        sock.close()
