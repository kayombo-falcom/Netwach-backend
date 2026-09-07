from django.db.models import QuerySet
from django.utils import timezone

from shared.repositories import BaseRepository

from devices.models import DeviceActivity, NetworkDevice


class NetworkDeviceRepository(BaseRepository[NetworkDevice]):
    model = NetworkDevice

    def list_all(self):
        return NetworkDevice.objects.all()

    def get_by_mac(self, mac: str) -> NetworkDevice | None:
        return NetworkDevice.objects.filter(mac=mac).first()

    def upsert_detection(
        self, *, mac, ip, os_family, os_name, os_version, device_type, confidence, signals
    ) -> NetworkDevice:
        device, _ = NetworkDevice.objects.update_or_create(
            mac=mac,
            defaults={
                "ip": ip,
                "os_family": os_family,
                "os_name": os_name,
                "os_version": os_version,
                "device_type": device_type,
                "confidence": confidence,
                "detection_method": NetworkDevice.DETECTION_ESTIMATED,
                "signals": signals,
                "last_detected_at": timezone.now(),
            },
        )
        return device


class DeviceActivityRepository(BaseRepository[DeviceActivity]):
    model = DeviceActivity

    def list_for_device(self, device_id) -> "QuerySet[DeviceActivity]":
        # Matches the (device, -timestamp) index in DeviceActivity.Meta.
        return DeviceActivity.objects.filter(device_id=device_id).order_by("-timestamp")

    def create(self, *, device_id, domain, source, timestamp, flagged) -> DeviceActivity:
        return DeviceActivity.objects.create(
            device_id=device_id, domain=domain, source=source, timestamp=timestamp, flagged=flagged,
        )
