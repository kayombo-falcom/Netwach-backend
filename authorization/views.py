from rest_framework import generics
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from authorization.models import ADMIN_ROLE_NAME, Role
from authorization.permissions import HasRole
from authorization.serializers import RolePermissionSerializer, RoleSerializer
from authorization.services import PermissionMatrixService, RoleService


class RoleListCreateView(generics.ListCreateAPIView):
    """Role list/create; create is Admin-only, gated directly by role so the permissions matrix can't lock out the ability to grant access."""

    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasRole(ADMIN_ROLE_NAME)()]
        return super().get_permissions()

    def perform_create(self, serializer):
        serializer.instance = RoleService().create_role(serializer.validated_data["name"])


class RoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Rename/delete a role, Admin-only; built-in roles are protected in RoleSerializer/RoleService, shared with the create path."""

    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    lookup_field = "name"
    permission_classes = [HasRole(ADMIN_ROLE_NAME)]

    def perform_update(self, serializer):
        serializer.instance = RoleService().rename_role(serializer.instance, serializer.validated_data["name"])

    def destroy(self, request: Request, *args, **kwargs) -> Response:
        role = self.get_object()
        RoleService().delete_role(role)
        return Response({"detail": "Role deleted."})


class RolePermissionsView(APIView):
    """Permission matrix read/patch; Admin-only by role, not by the matrix itself, so no edit here can lock every admin out."""

    permission_classes = [HasRole(ADMIN_ROLE_NAME)]

    def get(self, request: Request) -> Response:
        return Response(PermissionMatrixService().get_matrix())

    def patch(self, request: Request) -> Response:
        serializer = RolePermissionSerializer(data=request.data.get("updates", []), many=True)
        serializer.is_valid(raise_exception=True)
        return Response(PermissionMatrixService().apply_updates(serializer.validated_data))
