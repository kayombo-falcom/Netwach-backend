from django.db import transaction
from rest_framework.exceptions import ValidationError

from authorization.models import ADMIN_ROLE_NAME, Permission, Role
from authorization.repositories import RolePermissionRepository, RoleRepository


class RoleService:
    """Business rules for creating, renaming, and deleting roles.

    rename_role and delete_role are the two places this module reaches into
    `users` — see the dependency map in CONTRIBUTING.md.
    """

    def __init__(self, role_repo: RoleRepository | None = None, role_permission_repo: RolePermissionRepository | None = None):
        self.roles = role_repo or RoleRepository()
        self.role_permissions = role_permission_repo or RolePermissionRepository()

    def create_role(self, name: str) -> Role:
        role = self.roles.create(name=name)
        self.role_permissions.seed_for_role(role.name)
        return role

    def rename_role(self, role: Role, new_name: str) -> Role:
        """Cascades the rename to every RolePermission row and user referencing
        this role by name."""
        from users.repositories import UserRepository

        old_name = role.name
        if new_name == old_name:
            return role
        if role.is_builtin:
            raise ValidationError({"error": "Built-in roles can't be renamed."})

        with transaction.atomic():
            role.name = new_name
            self.roles.save(role)
            self.role_permissions.rename_role(old_name, new_name)
            UserRepository().reassign_role(old_name, new_name)
        return role

    def delete_role(self, role: Role) -> None:
        from users.repositories import UserRepository

        if role.is_builtin:
            raise ValidationError({"error": "Built-in roles can't be deleted."})
        if UserRepository().exists_with_role(role.name):
            raise ValidationError({"error": "Reassign that role's users before deleting it."})
        self.role_permissions.delete_for_role(role.name)
        self.roles.delete(role)


class PermissionMatrixService:
    """Role/permission grant matrix. Admins always show as fully granted;
    RolePermission rows only govern non-admin roles."""

    def __init__(self, role_repo: RoleRepository | None = None, role_permission_repo: RolePermissionRepository | None = None):
        self.roles = role_repo or RoleRepository()
        self.role_permissions = role_permission_repo or RolePermissionRepository()

    def get_matrix(self) -> list[dict]:
        role_names = list(self.roles.list_all().values_list("name", flat=True))
        rows = self.role_permissions.matrix_rows()
        return [
            {
                "permission": permission.value,
                "label": permission.label,
                "roles": {
                    name: True if name == ADMIN_ROLE_NAME else rows.get((name, permission.value), False)
                    for name in role_names
                },
            }
            for permission in Permission
        ]

    def apply_updates(self, updates: list[dict]) -> list[dict]:
        valid_roles = set(self.roles.list_all().values_list("name", flat=True))
        applicable = [
            update
            for update in updates
            # admins always have every permission; unknown roles are silently ignored
            if update["role"] != ADMIN_ROLE_NAME and update["role"] in valid_roles
        ]
        self.role_permissions.set_grants(applicable)
        return self.get_matrix()
