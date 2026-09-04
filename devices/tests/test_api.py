from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from authorization.models import ADMIN_ROLE_NAME
from devices.models import DeviceActivity, NetworkDevice
from users.models import User


class DeviceApiTests(APITestCase):
    def setUp(self):
        # Admins/Staff are seeded by authorization's initial migration.
        self.admin = User.objects.create_user(
            email="admin@example.com", password="Str0ngPassw0rd!", name="Admin", role=ADMIN_ROLE_NAME
        )
        self.client.force_authenticate(self.admin)

    def test_list_devices_requires_authentication(self):
        self.client.force_authenticate(None)

        response = self.client.get("/api/v1/devices/")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_devices(self):
        NetworkDevice.objects.create(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.10", os_family="Linux", signals=[])

        response = self.client.get("/api/v1/devices/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_post_detection_creates_device(self):
        response = self.client.post(
            "/api/v1/devices/detection/",
            {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "192.168.1.10",
                "os_family": "Windows",
                "os_name": "Windows 10/11",
                "os_version": None,
                "device_type": None,
                "confidence": 87,
                "signals": [{"source": "nmap", "detail": "Windows 10/11"}],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        device = NetworkDevice.objects.get(mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(device.ip, "192.168.1.10")
        self.assertEqual(device.os_name, "Windows 10/11")
        self.assertEqual(device.confidence, 87)
        self.assertEqual(device.detection_method, NetworkDevice.DETECTION_ESTIMATED)
        self.assertIsNotNone(device.last_detected_at)

    def test_post_detection_upserts_by_mac(self):
        NetworkDevice.objects.create(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.10", os_family="Linux", signals=[])

        self.client.post(
            "/api/v1/devices/detection/",
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "192.168.1.11",
                "os_family": "Windows",
                "os_name": "Windows 10/11",
                "confidence": 90,
            },
            format="json",
        )

        self.assertEqual(NetworkDevice.objects.count(), 1)
        device = NetworkDevice.objects.get(mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(device.ip, "192.168.1.11")
        self.assertEqual(device.os_family, "Windows")

    def test_post_detection_rejects_invalid_mac(self):
        response = self.client.post(
            "/api/v1/devices/detection/",
            {"mac": "not-a-mac", "ip": "192.168.1.10", "os_family": "Linux", "os_name": "Linux", "confidence": 80},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("mac", response.data)

    def test_list_devices_requires_devices_view_permission(self):
        staff = User.objects.create_user(email="staff@example.com", password="Str0ngPassw0rd!", name="Staff", role="Staff")
        self.client.force_authenticate(staff)

        response = self.client.get("/api/v1/devices/")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_post_detection_requires_devices_manage_permission(self):
        staff = User.objects.create_user(email="staff@example.com", password="Str0ngPassw0rd!", name="Staff", role="Staff")
        self.client.force_authenticate(staff)

        response = self.client.post(
            "/api/v1/devices/detection/",
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10", "os_family": "Linux", "os_name": "Linux", "confidence": 80},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_activity_returns_most_recent_first(self):
        device = NetworkDevice.objects.create(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.10", signals=[])
        older = DeviceActivity.objects.create(
            device=device, domain="old.example.com", source="dns", flagged=False,
            timestamp=timezone.now() - timezone.timedelta(minutes=5),
        )
        newer = DeviceActivity.objects.create(
            device=device, domain="new.example.com", source="dns", flagged=True, timestamp=timezone.now(),
        )

        response = self.client.get("/api/v1/devices/aa:bb:cc:dd:ee:ff/activity/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([row["id"] for row in response.data], [newer.id, older.id])

    def test_list_activity_is_scoped_to_the_device(self):
        device = NetworkDevice.objects.create(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.10", signals=[])
        other = NetworkDevice.objects.create(mac="11:22:33:44:55:66", ip="192.168.1.11", signals=[])
        DeviceActivity.objects.create(device=other, domain="other.example.com", source="dns", flagged=False, timestamp=timezone.now())

        response = self.client.get("/api/v1/devices/aa:bb:cc:dd:ee:ff/activity/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

    def test_list_activity_404s_for_unknown_mac(self):
        response = self.client.get("/api/v1/devices/aa:bb:cc:dd:ee:ff/activity/")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_list_activity_requires_devices_view_permission(self):
        NetworkDevice.objects.create(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.10", signals=[])
        staff = User.objects.create_user(email="staff@example.com", password="Str0ngPassw0rd!", name="Staff", role="Staff")
        self.client.force_authenticate(staff)

        response = self.client.get("/api/v1/devices/aa:bb:cc:dd:ee:ff/activity/")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
