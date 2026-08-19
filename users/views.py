from rest_framework import generics

from authorization.models import Permission
from authorization.permissions import HasPermission
from users.models import User
from users.serializers import UserSerializer, UserWriteSerializer


class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all().order_by("name")

    def get_serializer_class(self):
        return UserWriteSerializer if self.request.method == "POST" else UserSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasPermission(Permission.USERS_MANAGE)()]
        return super().get_permissions()


class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()

    def get_serializer_class(self):
        return UserSerializer if self.request.method == "GET" else UserWriteSerializer

    def get_permissions(self):
        if self.request.method in ("PUT", "PATCH"):
            return [HasPermission(Permission.USERS_MANAGE)()]
        return super().get_permissions()
