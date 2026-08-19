from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    """Creates users keyed by email instead of Django's default username."""

    use_in_migrations = True

    def create_user(self, email, password, name, role, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address.")
        user = self.model(email=self.normalize_email(email), name=name, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
