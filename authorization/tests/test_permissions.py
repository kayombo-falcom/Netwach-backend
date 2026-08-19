from django.test import TestCase
from rest_framework.test import APIRequestFactory

from authorization.models import ADMIN_ROLE_NAME, Permission, RolePermission
from authorization.permissions import HasPermission
from users.models import User


class HasPermissionTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def test_admin_always_passes_without_a_matrix_row(self):
        admin = User.objects.create_user(
            email="admin@example.com", password="Str0ngPassw0rd!", name="Admin", role=ADMIN_ROLE_NAME
        )
        request = self.factory.get("/")
        request.user = admin

        self.assertTrue(HasPermission(Permission.USERS_MANAGE)().has_permission(request, None))

    def test_non_admin_requires_an_explicit_grant(self):
        staff = User.objects.create_user(
            email="staff@example.com", password="Str0ngPassw0rd!", name="Staff", role="Staff"
        )
        request = self.factory.get("/")
        request.user = staff
        permission = HasPermission(Permission.USERS_MANAGE)()

        self.assertFalse(permission.has_permission(request, None))

        RolePermission.objects.create(role="Staff", permission=Permission.USERS_MANAGE, granted=True)

        self.assertTrue(permission.has_permission(request, None))
