from devices.models import NetworkDevice
from devices.repositories import NetworkDeviceRepository


class DeviceService:
    def __init__(self, device_repo: NetworkDeviceRepository | None = None):
        self.devices = device_repo or NetworkDeviceRepository()

    def list_devices(self):
        return self.devices.list_all()

    def record_detection(self, **kwargs) -> NetworkDevice:
        return self.devices.upsert_detection(**kwargs)
