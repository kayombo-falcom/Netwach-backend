from rest_framework import status
from rest_framework.test import APITestCase

from authorization.models import ADMIN_ROLE_NAME
from users.models import User


class UserApiTests(APITestCase):
    def setUp(self):
        # Admins/Staff are seeded by authorization's initial migration.
        self.admin = User.objects.create_user(
            email="admin@example.com", password="Str0ngPassw0rd!", name="Admin", role=ADMIN_ROLE_NAME
        )
        self.client.force_authenticate(self.admin)

    def test_create_user_rejects_unknown_role(self):
        response = self.client.post(
            "/api/v1/users/",
            {"name": "Bob", "email": "bob@example.com", "role": "Ghost", "password": "Str0ngPassw0rd!"},
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("role", response.data)
        self.assertFalse(User.objects.filter(email="bob@example.com").exists())

    def test_create_user_with_valid_role(self):
        response = self.client.post(
            "/api/v1/users/",
            {"name": "Bob", "email": "bob@example.com", "role": "Staff", "password": "Str0ngPassw0rd!"},
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email="bob@example.com").exists())

    def test_update_user_status_maps_to_is_active(self):
        user = User.objects.create_user(
            email="bob@example.com", password="Str0ngPassw0rd!", name="Bob", role="Staff"
        )

        response = self.client.patch(f"/api/v1/users/{user.id}/", {"status": "suspended"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    def test_update_user_ignores_password_field(self):
        user = User.objects.create_user(
            email="bob@example.com", password="Str0ngPassw0rd!", name="Bob", role="Staff"
        )
        original_password = user.password

        self.client.patch(f"/api/v1/users/{user.id}/", {"password": "SomethingElse123!"})

        user.refresh_from_db()
        self.assertEqual(user.password, original_password)
