from typing import Iterable

from shared.repositories import BaseRepository

from authorization.models import Permission, Role, RolePermission


class RoleRepository(BaseRepository[Role]):
    model = Role

    def list_all(self):
        return Role.objects.all()

    def get_by_name(self, name: str) -> Role | None:
        return Role.objects.filter(name=name).first()

    def exists(self, name: str) -> bool:
        return Role.objects.filter(name=name).exists()

    def create(self, name: str) -> Role:
        return Role.objects.create(name=name)

    def save(self, role: Role) -> Role:
        role.save()
        return role


class RolePermissionRepository(BaseRepository[RolePermission]):
    model = RolePermission

    def matrix_rows(self) -> dict[tuple[str, str], bool]:
        return {(r.role, r.permission): r.granted for r in RolePermission.objects.all()}

    def seed_for_role(self, role_name: str) -> None:
        """New roles start ungranted; access is opted in via the matrix."""
        RolePermission.objects.bulk_create(
            RolePermission(role=role_name, permission=permission, granted=False) for permission in Permission
        )

    def is_granted(self, role_name: str, permission: str) -> bool:
        return RolePermission.objects.filter(role=role_name, permission=permission, granted=True).exists()

    def set_grants(self, updates: Iterable[dict]) -> None:
        for update in updates:
            RolePermission.objects.update_or_create(
                role=update["role"],
                permission=update["permission"],
                defaults={"granted": update["granted"]},
            )

    def delete_for_role(self, role_name: str) -> None:
        RolePermission.objects.filter(role=role_name).delete()

    def rename_role(self, old_name: str, new_name: str) -> None:
        RolePermission.objects.filter(role=old_name).update(role=new_name)
