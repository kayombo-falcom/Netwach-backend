from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from devices.services import DeviceService
from network.hostname_resolve import lookup_device_hostname
from network.meta import get_network_meta
from network.os_fingerprint import detect_os
from network.packet_loss import measure_connection_packet_loss
from network.platform_linux import get_current_connection
from network.scanning import scan_connected_devices


class SafeGetView(APIView):
    """A GET-only view that runs `perform(request)` and turns any exception
    into a uniform 500 — every endpoint here is a live probe that can fail
    for reasons outside our control (unplugged cable, blocked port, a
    missing system tool, ...), and none of them should leak a traceback.
    `perform` returns either the response body, or a Response directly
    (e.g. a 400 for a bad request) to short-circuit the default 200."""

    error_message = "Request failed"

    def get(self, request: Request) -> Response:
        try:
            result = self.perform(request)
        except Exception:
            return Response({"error": self.error_message}, status=500)
        return result if isinstance(result, Response) else Response(result)

    def perform(self, request: Request):
        raise NotImplementedError


def _require_ip_param(request: Request) -> str | Response:
    """The "ip" query param, or a 400 Response if it's missing."""
    ip = request.query_params.get("ip")
    return ip if ip else Response({"error": 'Missing required "ip" query parameter'}, status=400)


class CurrentConnectionView(SafeGetView):
    """Live Wi-Fi/Ethernet status of whichever interface is carrying the default route."""

    error_message = "Unable to read network status on this host"

    def perform(self, request: Request):
        return get_current_connection()


class DevicesScanView(SafeGetView):
    """A live LAN scan (ping sweep + ARP table) — re-checked on every request, never cached."""

    error_message = "Unable to scan the local network"

    def perform(self, request: Request):
        return scan_connected_devices()


class HostnameLookupView(SafeGetView):
    """On-demand hostname lookup for one device (DNS/NetBIOS/mDNS chain)."""

    error_message = "Unable to resolve hostname"

    def perform(self, request: Request):
        ip = _require_ip_param(request)
        if isinstance(ip, Response):
            return ip
        return lookup_device_hostname(ip)


class OsDetectView(SafeGetView):
    """Runs a live nmap-backed OS detection against the requested host, and
    best-effort persists a "detected" result via the devices app so the
    device list/history survives across scans. A storage hiccup here must
    never fail the detection result the caller is looking at right now."""

    error_message = "Unable to run OS detection"

    def perform(self, request: Request):
        ip = _require_ip_param(request)
        if isinstance(ip, Response):
            return ip

        mac = request.query_params.get("mac")
        result = detect_os(ip, mac)
        if result.get("status") == "detected" and mac:
            self._persist_detection(mac, ip, result)
        return result

    @staticmethod
    def _persist_detection(mac: str, ip: str, result: dict) -> None:
        try:
            DeviceService().record_detection(
                mac=mac.lower(), ip=ip, os_family=result["osFamily"], os_name=result["osName"],
                os_version=result.get("osVersion"), device_type=result.get("deviceType"),
                confidence=result["confidence"], signals=result["signals"],
            )
        except Exception:
            pass


class PacketLossView(SafeGetView):
    """Runs a live batch of pings against a public target — never cached."""

    error_message = "Unable to measure packet loss"

    def perform(self, request: Request):
        return measure_connection_packet_loss()


class NetworkMetaView(SafeGetView):
    """ISP/location for whichever network this host's traffic actually travels over."""

    error_message = "Unable to read network location"

    def perform(self, request: Request):
        return get_network_meta()
