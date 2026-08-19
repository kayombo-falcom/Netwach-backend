from datetime import timedelta

from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from users.models import User


class AuthFlowTests(APITestCase):
    def setUp(self):
        # Staff is seeded by authorization's initial migration.
        self.user = User.objects.create_user(
            email="u@example.com", password="Str0ngPassw0rd!", name="U", role="Staff"
        )

    @override_settings(SECURITY_MAX_LOGIN_ATTEMPTS=3, SECURITY_LOCKOUT_DURATION_MINUTES=15)
    def test_account_locks_out_after_max_failed_attempts(self):
        for _ in range(3):
            response = self.client.post(
                "/api/v1/auth/login/", {"email": self.user.email, "password": "wrong-password"}
            )
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        response = self.client.post(
            "/api/v1/auth/login/", {"email": self.user.email, "password": "Str0ngPassw0rd!"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_successful_login_issues_tokens(self):
        response = self.client.post(
            "/api/v1/auth/login/", {"email": self.user.email, "password": "Str0ngPassw0rd!"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_refresh_rejected_after_password_change(self):
        login = self.client.post(
            "/api/v1/auth/login/", {"email": self.user.email, "password": "Str0ngPassw0rd!"}
        )
        refresh_token = login.data["refresh"]

        self.user.set_password("AnotherStr0ngPassw0rd!")
        self.user.save()

        response = self.client.post("/api/v1/auth/refresh/", {"refresh": refresh_token})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_change_password_invalidates_the_current_token(self):
        login = self.client.post(
            "/api/v1/auth/login/", {"email": self.user.email, "password": "Str0ngPassw0rd!"}
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['access']}")

        response = self.client.post(
            "/api/v1/auth/change-password/",
            {"current_password": "Str0ngPassw0rd!", "new_password": "AnotherStr0ngPassw0rd!"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        me_response = self.client.get("/api/v1/auth/me/")
        self.assertEqual(me_response.status_code, status.HTTP_401_UNAUTHORIZED)

    @override_settings(SECURITY_IDLE_SESSION_TIMEOUT_MINUTES=30)
    def test_idle_session_times_out(self):
        login = self.client.post(
            "/api/v1/auth/login/", {"email": self.user.email, "password": "Str0ngPassw0rd!"}
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['access']}")

        self.user.last_activity = timezone.now() - timedelta(minutes=31)
        self.user.save(update_fields=["last_activity"])

        response = self.client.get("/api/v1/auth/me/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
