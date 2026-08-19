from rest_framework import generics
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from authorization.models import ADMIN_ROLE_NAME, Role
from authorization.permissions import HasRole
from authorization.serializers import RolePermissionSerializer, RoleSerializer
from authorization.services import PermissionMatrixService, RoleService


class RoleListCreateView(generics.ListCreateAPIView):
    """The list of roles. Readable by any authenticated user — the Add/Edit User
    form needs it to populate its role dropdown — but only Admins can create
    new ones, restricted directly by role so the Roles & Permissions matrix
    itself can never lock that ability away."""

    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasRole(ADMIN_ROLE_NAME)()]
        return super().get_permissions()

    def perform_create(self, serializer):
        serializer.instance = RoleService().create_role(serializer.validated_data["name"])


class RoleDetailView(generics.DestroyAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    lookup_field = "name"
    permission_classes = [HasRole(ADMIN_ROLE_NAME)]

    def destroy(self, request: Request, *args, **kwargs) -> Response:
        role = self.get_object()
        RoleService().delete_role(role)
        return Response({"detail": "Role deleted."})


class RolePermissionsView(APIView):
    """The Roles & Permissions matrix: every (role, permission) pair and whether
    it's granted. Restricted to Admins directly by role — not by the matrix
    itself — so no combination of edits here can ever lock every admin out."""

    permission_classes = [HasRole(ADMIN_ROLE_NAME)]

    def get(self, request: Request) -> Response:
        return Response(PermissionMatrixService().get_matrix())

    def patch(self, request: Request) -> Response:
        serializer = RolePermissionSerializer(data=request.data.get("updates", []), many=True)
        serializer.is_valid(raise_exception=True)
        return Response(PermissionMatrixService().apply_updates(serializer.validated_data))
