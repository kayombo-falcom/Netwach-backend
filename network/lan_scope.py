from network.ip_utils import is_in_same_subnet
from network.platform_linux import get_current_connection


def is_ip_in_local_subnet(ip: str) -> bool:
    """Whether `ip` is on the same subnet as this host's current connection —
    the gate every on-demand network-probing endpoint needs (OS detection,
    hostname lookup, ...), so a request can't be pointed at an arbitrary
    external host instead of a device actually on this LAN."""
    connection = get_current_connection()
    return bool(connection["ip"]) and bool(connection["subnet"]) and is_in_same_subnet(ip, connection["ip"], connection["subnet"])
