from django.test import TestCase
from rest_framework.exceptions import ValidationError

from authorization.models import ADMIN_ROLE_NAME, Role, RolePermission
from authorization.services import PermissionMatrixService, RoleService
from users.models import User


class RoleServiceTests(TestCase):
    def test_create_role_seeds_ungranted_permissions(self):
        RoleService().create_role("Auditors")

        self.assertTrue(RolePermission.objects.filter(role="Auditors").exists())
        self.assertFalse(RolePermission.objects.filter(role="Auditors", granted=True).exists())

    def test_delete_role_rejects_builtin(self):
        # Admins is seeded as builtin by the initial migration.
        role = Role.objects.get(name=ADMIN_ROLE_NAME)

        with self.assertRaises(ValidationError):
            RoleService().delete_role(role)

    def test_delete_role_rejects_role_still_in_use(self):
        role = RoleService().create_role("Auditors")
        User.objects.create_user(email="x@example.com", password="Str0ngPassw0rd!", name="X", role="Auditors")

        with self.assertRaises(ValidationError):
            RoleService().delete_role(role)

    def test_delete_role_succeeds_when_unused(self):
        role = RoleService().create_role("Auditors")

        RoleService().delete_role(role)

        self.assertFalse(Role.objects.filter(name="Auditors").exists())
        self.assertFalse(RolePermission.objects.filter(role="Auditors").exists())


class PermissionMatrixServiceTests(TestCase):
    def test_admin_always_shows_as_granted(self):
        matrix = PermissionMatrixService().get_matrix()

        for row in matrix:
            self.assertTrue(row["roles"][ADMIN_ROLE_NAME])

    def test_apply_updates_ignores_admin_and_unknown_roles(self):
        RoleService().create_role("Auditors")

        PermissionMatrixService().apply_updates(
            [
                {"role": "Auditors", "permission": "users.view", "granted": True},
                {"role": ADMIN_ROLE_NAME, "permission": "users.view", "granted": False},
                {"role": "Ghost", "permission": "users.view", "granted": True},
            ]
        )

        self.assertTrue(
            RolePermission.objects.filter(role="Auditors", permission="users.view", granted=True).exists()
        )
        self.assertFalse(RolePermission.objects.filter(role="Ghost").exists())
