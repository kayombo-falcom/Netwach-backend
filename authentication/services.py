from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import User
from users.repositories import UserRepository


class AuthenticationService:
    """Owns the account-security policies layered on top of plain JWT auth:
    login lockout, refresh-after-password-change rejection, and self-service
    password change (which invalidates every outstanding session).
    """

    def __init__(self, user_repo: UserRepository | None = None):
        self.users = user_repo or UserRepository()

    def login(self, email: str, password: str) -> dict:
        user = self.users.get_by_email(email) if email else None

        if user and user.is_locked_out():
            raise ValidationError(
                "Account temporarily locked due to too many failed login attempts. Try again later."
            )

        token_serializer = TokenObtainPairSerializer(data={"email": email, "password": password})
        try:
            token_serializer.is_valid(raise_exception=True)
        except Exception:
            if user:
                user.register_failed_login()
            raise

        user.register_successful_login()
        return token_serializer.validated_data

    def refresh(self, raw_refresh_token: str) -> dict:
        refresh = RefreshToken(raw_refresh_token)
        user_id = refresh.payload.get(api_settings.USER_ID_CLAIM)
        issued_at = refresh.payload.get("iat")

        if user_id and issued_at:
            user = self.users.get_by_id(user_id)
            if user and user.is_password_stale(issued_at):
                raise AuthenticationFailed("Your password was recently changed. Please log in again.")

        token_serializer = TokenRefreshSerializer(data={"refresh": raw_refresh_token})
        token_serializer.is_valid(raise_exception=True)
        return token_serializer.validated_data

    def change_password(self, user: User, current_password: str, new_password: str) -> User:
        if not user.check_password(current_password):
            raise ValidationError({"current_password": "Current password is incorrect."})

        try:
            password_validation.validate_password(new_password, user=user)
        except DjangoValidationError as exc:
            raise ValidationError({"new_password": exc.messages})

        user.set_password(new_password)
        return self.users.save(user, update_fields=["password", "password_changed_at"])
