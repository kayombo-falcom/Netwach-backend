from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils import timezone

from accounts.managers import UserManager


class Role(models.TextChoices):
    ADMIN = "Admins", "Admins"
    STAFF = "Staff", "Staff"
    STUDENT = "Students", "Students"
    GUEST = "Guests", "Guests"
    IOT = "IoT", "IoT"


class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=150)
    role = models.CharField(max_length=20, choices=Role.choices)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    # Account-lockout policy state (see register_failed_login/register_successful_login).
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    # Idle-session-timeout policy state, refreshed on every authenticated request
    # by accounts.authentication.IdleTimeoutJWTAuthentication.
    last_activity = models.DateTimeField(null=True, blank=True)

    # Bumped by set_password() below; any JWT issued before this moment is treated
    # as stale (see is_password_stale) so a password change forces a fresh login
    # everywhere, not just on the device that changed it.
    password_changed_at = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "role"]

    def __str__(self):
        return self.email

    def set_password(self, raw_password: str) -> None:
        super().set_password(raw_password)
        self.password_changed_at = timezone.now()

    def is_password_stale(self, token_issued_at: int) -> bool:
        """True if a JWT with this `iat` (unix timestamp) claim predates the last
        password change and should no longer be honored."""
        issued = datetime.fromtimestamp(token_issued_at, tz=dt_timezone.utc)
        return issued < self.password_changed_at

    def is_locked_out(self) -> bool:
        return bool(self.locked_until and timezone.now() < self.locked_until)

    def register_failed_login(self) -> None:
        """Records a failed login attempt, locking the account once
        SECURITY_MAX_LOGIN_ATTEMPTS is reached."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= settings.SECURITY_MAX_LOGIN_ATTEMPTS:
            self.locked_until = timezone.now() + timedelta(
                minutes=settings.SECURITY_LOCKOUT_DURATION_MINUTES
            )
        self.save(update_fields=["failed_login_attempts", "locked_until"])

    def register_successful_login(self) -> None:
        """Clears any lockout state after a successful authentication."""
        if self.failed_login_attempts or self.locked_until:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save(update_fields=["failed_login_attempts", "locked_until"])
