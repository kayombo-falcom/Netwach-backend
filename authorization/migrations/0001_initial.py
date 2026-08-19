from django.db import migrations, models

from authorization.models import ADMIN_ROLE_NAME, STAFF_ROLE_NAME


def seed_builtin_roles(apps, schema_editor):
    Role = apps.get_model("authorization", "Role")
    Role.objects.get_or_create(name=ADMIN_ROLE_NAME, defaults={"is_builtin": True})
    Role.objects.get_or_create(name=STAFF_ROLE_NAME, defaults={"is_builtin": True})


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Role",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=40, unique=True)),
                ("is_builtin", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ["-is_builtin", "name"],
            },
        ),
        migrations.CreateModel(
            name="RolePermission",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("role", models.CharField(max_length=40)),
                (
                    "permission",
                    models.CharField(
                        choices=[
                            ("users.view", "View users"),
                            ("users.manage", "Create & edit users"),
                            ("devices.view", "View devices"),
                            ("devices.manage", "Manage devices"),
                            ("access_points.view", "View access points"),
                            ("access_points.manage", "Manage access points"),
                            ("policies.view", "View policies"),
                            ("policies.manage", "Manage policies"),
                            ("traffic.view", "View traffic reports"),
                            ("alerts.view", "View alerts"),
                            ("alerts.manage", "Manage alerts"),
                            ("settings.manage", "Manage settings"),
                        ],
                        max_length=40,
                    ),
                ),
                ("granted", models.BooleanField(default=False)),
            ],
            options={
                "unique_together": {("role", "permission")},
            },
        ),
        migrations.RunPython(seed_builtin_roles, migrations.RunPython.noop),
    ]
