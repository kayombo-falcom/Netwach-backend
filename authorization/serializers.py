from rest_framework import serializers

from authorization.models import Permission, Role


class RoleSerializer(serializers.ModelSerializer):
    """Create/list shape for custom roles. Built-in roles (Admins/Staff) are
    seeded by migration and can't be created or renamed through this endpoint."""

    class Meta:
        model = Role
        fields = ["name", "is_builtin"]
        read_only_fields = ["is_builtin"]

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Role name is required.")
        return value


class RolePermissionSerializer(serializers.Serializer):
    """One edit to the roles/permissions matrix: whether `permission` should be
    granted to `role`. `role` isn't a ChoiceField since roles are created at
    runtime — the service checks it against the live Role table instead."""

    role = serializers.CharField()
    permission = serializers.ChoiceField(choices=Permission.choices)
    granted = serializers.BooleanField()
