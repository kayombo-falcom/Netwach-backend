from rest_framework import serializers

from authorization.models import Permission, Role


class RoleSerializer(serializers.ModelSerializer):
    """Create/list/rename shape for roles. Built-in roles (Admins/Staff) are
    seeded by migration and can't be renamed."""

    class Meta:
        model = Role
        fields = ["name", "is_builtin"]
        read_only_fields = ["is_builtin"]

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Role name is required.")
        if self.instance and self.instance.is_builtin and value != self.instance.name:
            raise serializers.ValidationError("Built-in roles can't be renamed.")
        return value


class RolePermissionSerializer(serializers.Serializer):
    """One matrix edit: whether `permission` is granted to `role`. `role` is a
    plain CharField, not a ChoiceField, since roles are created at runtime."""

    role = serializers.CharField()
    permission = serializers.ChoiceField(choices=Permission.choices)
    granted = serializers.BooleanField()
