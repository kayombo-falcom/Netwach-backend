from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication


class IdleTimeoutJWTAuthentication(JWTAuthentication):
    """JWTAuthentication plus the idle-session-timeout and password-change policies.

    A token that is otherwise valid stops authenticating once its user has been
    inactive for longer than SECURITY_IDLE_SESSION_TIMEOUT_MINUTES, or once it was
    issued before the user's password was last changed — forcing re-login in both
    cases even though the token itself hasn't expired yet. Every authenticated
    request refreshes the user's activity timestamp.
    """

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
