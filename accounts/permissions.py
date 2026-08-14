from rest_framework.permissions import BasePermission


def HasRole(*roles):
    """Builds a DRF permission class restricting a view to the given user roles.

    Usage: permission_classes = [HasRole(Role.ADMIN, Role.STAFF)]
    """

    class _HasRole(BasePermission):
        def has_permission(self, request, view):
            return bool(request.user and request.user.is_authenticated and request.user.role in roles)

    return _HasRole
