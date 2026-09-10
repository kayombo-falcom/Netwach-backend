from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication


class IdleTimeoutJWTAuthentication(JWTAuthentication):
    """JWTAuthentication plus idle-session-timeout and password-change policies: a token stops authenticating after too much inactivity or if issued before the last password change, even though it hasn't expired. Every authenticated request refreshes the activity timestamp."""

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None

        user, validated_token = result

        if user.is_password_stale(validated_token["iat"]):
            raise AuthenticationFailed("Your password was recently changed. Please log in again.")

        now = timezone.now()
        timeout = timedelta(minutes=settings.SECURITY_IDLE_SESSION_TIMEOUT_MINUTES)
        if user.last_activity and now - user.last_activity > timeout:
            raise AuthenticationFailed("Session expired due to inactivity. Please log in again.")

        user.last_activity = now
        user.save(update_fields=["last_activity"])

        return user, validated_token
