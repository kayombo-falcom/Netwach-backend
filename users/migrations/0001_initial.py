import django.utils.timezone
from django.db import migrations, models

import users.managers


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                ("last_login", models.DateTimeField(blank=True, null=True, verbose_name="last login")),
                ("email", models.EmailField(max_length=254, unique=True)),
                ("name", models.CharField(max_length=150)),
                ("role", models.CharField(max_length=40)),
                ("is_active", models.BooleanField(default=True)),
                ("date_joined", models.DateTimeField(auto_now_add=True)),
                ("failed_login_attempts", models.PositiveIntegerField(default=0)),
                ("locked_until", models.DateTimeField(blank=True, null=True)),
                ("last_activity", models.DateTimeField(blank=True, null=True)),
                ("password_changed_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                "abstract": False,
            },
            managers=[
                ("objects", users.managers.UserManager()),
            ],
        ),
    ]
