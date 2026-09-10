from rest_framework import serializers

from devices.models import DeviceActivity, NetworkDevice
from devices.services import DeviceService

MAC_PATTERN = r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"


class NetworkDeviceSerializer(serializers.ModelSerializer):
    """Read shape for the persisted device list/detection result."""

    class Meta:
        model = NetworkDevice
        fields = [
            "mac", "ip", "hostname", "os_family", "os_name", "os_version", "device_type",
            "confidence", "detection_method", "signals", "first_seen_at", "last_seen_at", "last_detected_at",
        ]
        read_only_fields = fields


class DeviceActivitySerializer(serializers.ModelSerializer):
    """Read shape for one device's activity feed (GET /devices/<mac>/activity/)."""

    class Meta:
        model = DeviceActivity
        fields = ["id", "domain", "source", "timestamp", "flagged"]
        read_only_fields = fields


class DeviceDetectionSerializer(serializers.Serializer):
    """Write shape for POST /devices/detection/; `detection_method` isn't client-supplied since every result today is "estimated" until self-reporting exists."""

    mac = serializers.RegexField(MAC_PATTERN)
    ip = serializers.IPAddressField(protocol="IPv4")
    os_family = serializers.CharField(max_length=40)
    os_name = serializers.CharField(max_length=120)
    os_version = serializers.CharField(max_length=60, allow_null=True, required=False)
    device_type = serializers.CharField(max_length=60, allow_null=True, required=False)
    confidence = serializers.IntegerField(min_value=0, max_value=100)
    signals = serializers.ListField(child=serializers.DictField(), required=False, default=list)

    def save(self) -> NetworkDevice:
        data = self.validated_data
        return DeviceService().record_detection(
            mac=data["mac"].lower(),
            ip=data["ip"],
            os_family=data["os_family"],
            os_name=data["os_name"],
            os_version=data.get("os_version"),
            device_type=data.get("device_type"),
            confidence=data["confidence"],
            signals=data.get("signals", []),
        )
