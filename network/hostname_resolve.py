"""Best-effort hostname for a LAN IP: reverse DNS rarely works on home networks, so NetBIOS and mDNS are tried next, each only if the prior one came up empty."""

import socket
import threading

from network.lan_scope import is_ip_in_local_subnet
from network.mdns_client import resolve_ptr
from network.netbios import query_netbios_name

DNS_TIMEOUT_S = 0.8
NETBIOS_TIMEOUT_S = 0.4
MDNS_TIMEOUT_S = 0.6


def _resolve_dns_ptr(ip: str) -> str | None:
    """Classic reverse DNS — only works if the router tracks PTR records, which most consumer routers don't; raced on a daemon thread against a timeout rather than blocking on the OS resolver's own longer one."""
    result: dict = {}
    done = threading.Event()

    def lookup():
        try:
            result["name"] = socket.gethostbyaddr(ip)[0]
        except OSError:
            pass
        finally:
            done.set()

    threading.Thread(target=lookup, daemon=True).start()
    done.wait(DNS_TIMEOUT_S)
    return result.get("name")


def _resolve_mdns_name(ip: str) -> str | None:
    """mDNS (Bonjour) reverse-PTR query over multicast — asks the device directly, the way Apple (and increasingly Android/IoT) devices announce a name."""
    ptr_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    return resolve_ptr(ptr_name, MDNS_TIMEOUT_S)


def _resolve_hostname(ip: str) -> str | None:
    return _resolve_dns_ptr(ip) or query_netbios_name(ip, NETBIOS_TIMEOUT_S) or _resolve_mdns_name(ip)


def lookup_device_hostname(ip: str) -> dict:
    if not is_ip_in_local_subnet(ip):
        return {"status": "out_of_scope"}
    hostname = _resolve_hostname(ip)
    return {"status": "resolved", "hostname": hostname} if hostname else {"status": "not_found"}
