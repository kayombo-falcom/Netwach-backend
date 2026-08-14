from rest_framework import serializers

from accounts.models import User


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
