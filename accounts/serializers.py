from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import User


class LoginSerializer(TokenObtainPairSerializer):
    """TokenObtainPairSerializer plus the account-lockout policy: locked accounts
    are rejected up front, and each failed attempt against a real account counts
    toward its lockout threshold (see User.register_failed_login)."""

    def validate(self, attrs):
        email = attrs.get(self.username_field)
        user = User.objects.filter(email__iexact=email).first() if email else None

        if user and user.is_locked_out():
            raise serializers.ValidationError(
                "Account temporarily locked due to too many failed login attempts. "
                "Try again later."
            )

        try:
            data = super().validate(attrs)
        except Exception:
            if user:
                user.register_failed_login()
            raise

        user.register_successful_login()
        return data


class PasswordAwareTokenRefreshSerializer(TokenRefreshSerializer):
    """TokenRefreshSerializer plus the password-change policy: a refresh token
    issued before the user's password was last changed can no longer mint new
    access tokens (see User.is_password_stale)."""

    def validate(self, attrs):
        refresh = RefreshToken(attrs["refresh"])
        user_id = refresh.payload.get(api_settings.USER_ID_CLAIM)
        issued_at = refresh.payload.get("iat")

        if user_id and issued_at:
            user = User.objects.filter(**{api_settings.USER_ID_FIELD: user_id}).first()
            if user and user.is_password_stale(issued_at):
                raise AuthenticationFailed("Your password was recently changed. Please log in again.")

        return super().validate(attrs)


class ChangePasswordSerializer(serializers.Serializer):
    """Validates a self-service password change. Saving it (via `save()`) updates
    User.password_changed_at, which invalidates every outstanding session/token —
    including the one used to make this request."""

    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate_current_password(self, value):
        if not self.context["request"].user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate_new_password(self, value):
        try:
            password_validation.validate_password(value, user=self.context["request"].user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value

    def save(self):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save(update_fields=["password", "password_changed_at"])
        return user


class UserSerializer(serializers.ModelSerializer):
    """Read shape for the users list/detail — derives `status` from `is_active` so the
    frontend never has to know about the boolean."""

    status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "name", "email", "role", "status", "last_login", "date_joined"]

    def get_status(self, obj: User) -> str:
        return "active" if obj.is_active else "suspended"


class UserWriteSerializer(serializers.ModelSerializer):
    """Create/update shape. `status` is accepted as active/suspended and mapped to
    `is_active`; `password` is required on create only (updates don't change it)."""

    status = serializers.ChoiceField(choices=["active", "suspended"], required=False)
    password = serializers.CharField(write_only=True, required=False, min_length=8)

    class Meta:
        model = User
        fields = ["id", "name", "email", "role", "status", "password"]
        read_only_fields = ["id"]

    def validate(self, attrs):
        if self.instance is None and not attrs.get("password"):
            raise serializers.ValidationError({"password": "Password is required to create a user."})
        return attrs

    def create(self, validated_data):
        status = validated_data.pop("status", "active")
        password = validated_data.pop("password")
        return User.objects.create_user(is_active=status == "active", password=password, **validated_data)

    def update(self, instance, validated_data):
        status = validated_data.pop("status", None)
        validated_data.pop("password", None)
        if status is not None:
            instance.is_active = status == "active"
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
