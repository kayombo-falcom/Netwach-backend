from django.db import models


class NetworkDevice(models.Model):
    """A device seen on the LAN, identified by MAC. Live scanning/probing
    (ARP, ping sweep, nmap OS fingerprinting, mDNS/SSDP/NetBIOS) stays in the
    Next.js frontend — it depends on that server's own network position, not
    on where this backend runs. This only persists what the frontend
    reports, so device identity and OS-detection history survive restarts
    and repeated scans instead of living only in the browser session.
    """

    DETECTION_ESTIMATED = "estimated"
    DETECTION_VERIFIED = "verified"

    mac = models.CharField(max_length=17, unique=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    hostname = models.CharField(max_length=255, null=True, blank=True)

    os_family = models.CharField(max_length=40, null=True, blank=True)
    os_name = models.CharField(max_length=120, null=True, blank=True)
    os_version = models.CharField(max_length=60, null=True, blank=True)
    device_type = models.CharField(max_length=60, null=True, blank=True)
    confidence = models.PositiveSmallIntegerField(null=True, blank=True)
    detection_method = models.CharField(max_length=20, null=True, blank=True)
    signals = models.JSONField()

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    last_detected_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-last_seen_at"]

    def __str__(self):
        return self.mac


class DeviceActivity(models.Model):
    """A domain a device was seen contacting. Read via GET
    /devices/<mac>/activity/ (the device drawer's "Recent activity" list);
    nothing writes to it yet — that needs real DNS/traffic-capture
    infrastructure, a separate feature from this read path."""

    domain = models.CharField(max_length=255)
    source = models.CharField(max_length=20)
    timestamp = models.DateTimeField()
    flagged = models.BooleanField()
    device = models.ForeignKey(NetworkDevice, on_delete=models.PROTECT, related_name="activity")

    class Meta:
        verbose_name_plural = "device activity"
        indexes = [models.Index(fields=["device", "-timestamp"])]

    def __str__(self):
        return f"{self.device_id}:{self.domain}"
