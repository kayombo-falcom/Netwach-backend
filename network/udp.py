"""Shared "send one UDP packet, wait for a matching reply" loop used by mDNS/SSDP/NetBIOS, so the deadline logic lives in one place."""

import socket
import time

# Sentinel meaning "not my answer, keep waiting" — distinct from a legitimate stop-and-return-None result.
CONTINUE = object()


def recv_until(sock: socket.socket, timeout_s: float, on_packet):
    """Loops recvfrom until on_packet returns something other than CONTINUE, or timeout_s elapses; re-arms the timeout each round so stray packets can't extend the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(65535)
        except OSError:
            return None
        result = on_packet(data, addr)
        if result is not CONTINUE:
            return result
