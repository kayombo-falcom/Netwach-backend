from rest_framework import serializers


class LoginRequestSerializer(serializers.Serializer):
    """Field-shape only — credential verification and lockout policy live in AuthenticationService."""

    email = serializers.CharField()
    password = serializers.CharField(write_only=True)


class RefreshRequestSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ChangePasswordRequestSerializer(serializers.Serializer):
    """Field-shape only — verifying the current password and validating the new one live in AuthenticationService."""

    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
