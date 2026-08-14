import os

from django.core.management.base import BaseCommand

from accounts.models import Role, User


class Command(BaseCommand):
    help = "Creates the initial admin user from ADMIN_EMAIL/ADMIN_PASSWORD/ADMIN_NAME env vars, if one doesn't already exist."

    def handle(self, *args, **options):
        email = os.environ.get("ADMIN_EMAIL", "admin@netwatch.io")
        password = os.environ.get("ADMIN_PASSWORD")
        name = os.environ.get("ADMIN_NAME", "Admin")

        if not password:
            self.stderr.write(self.style.ERROR("ADMIN_PASSWORD env var is required to seed the admin user."))
            return

        if User.objects.filter(email=email).exists():
            self.stdout.write(self.style.WARNING(f"Admin user '{email}' already exists — skipping."))
            return

        User.objects.create_user(email=email, password=password, name=name, role=Role.ADMIN)
        self.stdout.write(self.style.SUCCESS(f"Created admin user '{email}'."))
