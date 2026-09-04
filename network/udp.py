"""Shared "send one UDP packet, wait for a matching reply" loop used by the
mDNS/SSDP/NetBIOS probes — one place to get the deadline math right instead
of three near-identical copies of it."""

import socket
import time

# Sentinel an on_packet callback returns to mean "not my answer, keep
# waiting" — distinct from a legitimate stop-and-return-None result (e.g.
# NetBIOS: the transaction ID matched, but the response had no usable name).
CONTINUE = object()


def recv_until(sock: socket.socket, timeout_s: float, on_packet):
    """Loops recvfrom on `sock` until on_packet(data, addr) returns
    something other than CONTINUE, or timeout_s elapses in total. Re-arms
    the socket timeout to the *remaining* time each iteration, so a burst of
    irrelevant packets can't extend the wait past timeout_s."""
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
