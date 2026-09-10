from network.ip_utils import is_in_same_subnet
from network.platform_linux import get_current_connection


def is_ip_in_local_subnet(ip: str) -> bool:
    """Whether `ip` is on this host's current subnet — the gate every probing endpoint needs so a request can't target a host outside this LAN."""
    connection = get_current_connection()
    return bool(connection["ip"]) and bool(connection["subnet"]) and is_in_same_subnet(ip, connection["ip"], connection["subnet"])
