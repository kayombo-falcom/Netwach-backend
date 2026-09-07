from django.core.management.base import BaseCommand

from network.arp_mitm import run_forever


class Command(BaseCommand):
    help = (
        "Continuously ARP-spoofs known LAN devices to redirect their traffic through this host "
        "(with IP forwarding) so capture_dns can see it. Must be explicitly enabled via "
        "ARP_MITM_ENABLED — can disrupt every device's connectivity if misconfigured."
    )

    def handle(self, *args, **options):
        run_forever()
