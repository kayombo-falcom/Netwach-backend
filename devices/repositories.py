from django.utils import timezone

from shared.repositories import BaseRepository

from devices.models import NetworkDevice


class NetworkDeviceRepository(BaseRepository[NetworkDevice]):
    model = NetworkDevice

    def list_all(self):
        return NetworkDevice.objects.all()

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
