from rest_framework import generics
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Role, User
from accounts.permissions import HasRole
from accounts.serializers import UserSerializer, UserWriteSerializer


class MeView(APIView):
    """Confirms the bearer token is valid and its user still exists and is active.

    JWTAuthentication already re-fetches the user from the database per request and
    rejects the token if the user was deleted or deactivated since it was issued.
    """

    def get(self, request: Request) -> Response:
        user = request.user
        return Response({"id": user.id, "email": user.email, "name": user.name, "role": user.role})


class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all().order_by("name")

    def get_serializer_class(self):
        return UserWriteSerializer if self.request.method == "POST" else UserSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [HasRole(Role.ADMIN)()]
        return super().get_permissions()


class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()

    def get_serializer_class(self):
        return UserSerializer if self.request.method == "GET" else UserWriteSerializer

    def get_permissions(self):
        if self.request.method in ("PUT", "PATCH"):
            return [HasRole(Role.ADMIN)()]
        return super().get_permissions()
