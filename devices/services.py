from devices.models import NetworkDevice
from devices.repositories import DeviceActivityRepository, NetworkDeviceRepository


class DeviceService:
    def __init__(
        self,
        device_repo: NetworkDeviceRepository | None = None,
        activity_repo: DeviceActivityRepository | None = None,
    ):
        self.devices = device_repo or NetworkDeviceRepository()
        self.activity = activity_repo or DeviceActivityRepository()

    def list_devices(self):
        return self.devices.list_all()

    def get_by_mac(self, mac: str) -> NetworkDevice | None:
        return self.devices.get_by_mac(mac.lower())

    def list_activity(self, device: NetworkDevice):
        return self.activity.list_for_device(device.id)

    def record_detection(self, **kwargs) -> NetworkDevice:
        return self.devices.upsert_detection(**kwargs)
