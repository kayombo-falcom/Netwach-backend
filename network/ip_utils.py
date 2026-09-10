"""Pure IPv4 arithmetic, shared by device discovery's host-range sweep and OS fingerprinting's scope check."""


def ip_to_long(ip: str) -> int:
    total = 0
    for octet in ip.split("."):
        total = (total << 8) + int(octet)
    return total & 0xFFFFFFFF


def long_to_ip(value: int) -> str:
    return ".".join(str((value >> shift) & 255) for shift in (24, 16, 8, 0))


def is_in_same_subnet(ip: str, local_ip: str, mask: str) -> bool:
    """Whether `ip` is in the same subnet as `local_ip` under `mask` (e.g. both on the same /24)."""
    mask_long = ip_to_long(mask)
    return (ip_to_long(ip) & mask_long) == (ip_to_long(local_ip) & mask_long)


def mask_to_cidr(mask: str) -> int:
    """Dotted mask (e.g. 255.255.255.0) to its CIDR prefix length (e.g. 24)."""
    return bin(ip_to_long(mask)).count("1")


def cidr_to_mask(prefix_len: int) -> str:
    """CIDR prefix length (e.g. 24, from `ip addr`'s prefixlen) to its dotted mask."""
    bits = 0 if prefix_len == 0 else (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return long_to_ip(bits)
