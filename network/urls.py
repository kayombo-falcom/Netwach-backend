from django.urls import path

from network.views import (
    CurrentConnectionView, DevicesScanView, HostnameLookupView,
    NetworkMetaView, OsDetectView, PacketLossView,
)

urlpatterns = [
    path("current/", CurrentConnectionView.as_view(), name="network-current"),
    path("devices/", DevicesScanView.as_view(), name="network-devices"),
    path("hostname/", HostnameLookupView.as_view(), name="network-hostname"),
    path("os-detect/", OsDetectView.as_view(), name="network-os-detect"),
    path("packet-loss/", PacketLossView.as_view(), name="network-packet-loss"),
    path("meta/", NetworkMetaView.as_view(), name="network-meta"),
]
