from rest_framework.exceptions import ValidationError

from authorization.models import ADMIN_ROLE_NAME, Permission, Role
from authorization.repositories import RolePermissionRepository, RoleRepository


class RoleService:
    """Owns the business rules around creating/deleting roles.

    delete_role's "is this role still in use" check is the one place
    `authorization` reaches into `users` — see the cross-module dependency
    note in the architecture plan. If `authorization` is ever split out into
    its own service, this is the seam to replace with an API/event call.
    """

    def __init__(self, role_repo: RoleRepository | None = None, role_permission_repo: RolePermissionRepository | None = None):
        self.roles = role_repo or RoleRepository()
        self.role_permissions = role_permission_repo or RolePermissionRepository()

    def create_role(self, name: str) -> Role:
        role = self.roles.create(name=name)
        self.role_permissions.seed_for_role(role.name)
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
    """The Roles & Permissions matrix: every (role, permission) pair and whether
    it's granted. Admins always show as granted for everything, regardless of
    what's stored — RolePermission only ever governs non-admin roles."""

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
