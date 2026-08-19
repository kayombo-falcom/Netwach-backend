from rest_framework import serializers

from users.models import User
from users.services import UserService


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
    `is_active`; `password` is required on create only (updates don't change it).
    Role validity and the actual persistence are handled by UserService."""

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
        return UserService().create_user(
            name=validated_data["name"],
            email=validated_data["email"],
            role=validated_data["role"],
            password=validated_data["password"],
            status=validated_data.get("status", "active"),
        )

    def update(self, instance, validated_data):
        validated_data.pop("password", None)  # updates never change the password; use change-password instead
        return UserService().update_user(instance, **validated_data)
