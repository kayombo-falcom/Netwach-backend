from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from users.models import User


class UserPolicyTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="a@example.com", password="Str0ngPassw0rd!", name="A", role="Staff"
        )

    @override_settings(SECURITY_MAX_LOGIN_ATTEMPTS=3, SECURITY_LOCKOUT_DURATION_MINUTES=15)
    def test_locks_out_after_max_failed_attempts(self):
        for _ in range(3):
            self.user.register_failed_login()
        self.assertTrue(self.user.is_locked_out())

    def test_successful_login_clears_lockout_state(self):
        self.user.failed_login_attempts = 5
        self.user.locked_until = timezone.now() + timedelta(minutes=10)
        self.user.save()

        self.user.register_successful_login()

        self.assertFalse(self.user.is_locked_out())
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_password_change_makes_previously_issued_tokens_stale(self):
        issued_before = int(timezone.now().timestamp())
        self.user.set_password("NewStr0ngPassw0rd!")
        self.user.save()

        self.assertTrue(self.user.is_password_stale(issued_before))
