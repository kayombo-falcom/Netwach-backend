from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models

from accounts.managers import UserManager


class Role(models.TextChoices):
    ADMIN = "Admins", "Admins"
    STAFF = "Staff", "Staff"
    STUDENT = "Students", "Students"
    GUEST = "Guests", "Guests"
    IOT = "IoT", "IoT"


class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=150)
    role = models.CharField(max_length=20, choices=Role.choices)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "role"]

    def __str__(self):
        return self.email
