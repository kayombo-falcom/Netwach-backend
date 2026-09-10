from django.db import models

# Bypasses the permissions matrix entirely; a fixed name, not a row, so it can never be renamed/deleted into zero working admins.
ADMIN_ROLE_NAME = "Admins"
STAFF_ROLE_NAME = "Staff"


class Role(models.Model):
    """A named group users can belong to; Admins/Staff are seeded as built-in and can't be renamed or deleted."""

    name = models.CharField(max_length=40, unique=True)
    is_builtin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-is_builtin", "name"]

    def __str__(self):
        return self.name


class Permission(models.TextChoices):
    """Catalog of grantable actions; Admins implicitly hold all of them, so RolePermission only governs non-admin roles."""

    USERS_VIEW = "users.view", "View users"
    USERS_MANAGE = "users.manage", "Create & edit users"
    DEVICES_VIEW = "devices.view", "View devices"
    DEVICES_MANAGE = "devices.manage", "Manage devices"
    ACCESS_POINTS_VIEW = "access_points.view", "View access points"
    ACCESS_POINTS_MANAGE = "access_points.manage", "Manage access points"
    POLICIES_VIEW = "policies.view", "View policies"
    POLICIES_MANAGE = "policies.manage", "Manage policies"
    TRAFFIC_VIEW = "traffic.view", "View traffic reports"
    ALERTS_VIEW = "alerts.view", "View alerts"
    ALERTS_MANAGE = "alerts.manage", "Manage alerts"
    SETTINGS_MANAGE = "settings.manage", "Manage settings"


class RolePermission(models.Model):
    """Whether `permission` is granted to `role`; never consulted for Admins, who always pass."""

    role = models.CharField(max_length=40)
    permission = models.CharField(max_length=40, choices=Permission.choices)
    granted = models.BooleanField(default=False)

    class Meta:
        unique_together = ("role", "permission")

    def __str__(self):
        return f"{self.role}:{self.permission}={self.granted}"
