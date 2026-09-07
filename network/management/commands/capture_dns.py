from django.core.management.base import BaseCommand

from network.dns_capture import run_forever


class Command(BaseCommand):
    help = "Continuously captures LAN DNS queries and persists them as DeviceActivity rows. Long-running — never run inside a request-serving worker."

    def handle(self, *args, **options):
        run_forever()
