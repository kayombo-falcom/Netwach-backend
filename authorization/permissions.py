from rest_framework.permissions import BasePermission

from authorization.models import ADMIN_ROLE_NAME
from authorization.repositories import RolePermissionRepository


def HasRole(*role_names):
    """Builds a DRF permission class restricting a view to the given role names. Usage: permission_classes = [HasRole(ADMIN_ROLE_NAME)]"""

    class _HasRole(BasePermission):
        def has_permission(self, request, view):
            return bool(request.user and request.user.is_authenticated and request.user.role in role_names)

    return _HasRole


def HasPermission(permission):
    """Builds a DRF permission class gating a view on the roles/permissions matrix; Admins always pass regardless of RolePermission, so that table can never lock every admin out.
    Usage: permission_classes = [HasPermission(Permission.USERS_MANAGE)]"""

    class _HasPermission(BasePermission):
        def has_permission(self, request, view):
            user = request.user
            if not (user and user.is_authenticated):
                return False
            if user.role == ADMIN_ROLE_NAME:
                return True
            return RolePermissionRepository().is_granted(user.role, permission)

    return _HasPermission
