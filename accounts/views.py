from rest_framework import generics
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from accounts.models import Role, User
from accounts.permissions import HasRole
from accounts.serializers import (
    ChangePasswordSerializer,
    LoginSerializer,
    PasswordAwareTokenRefreshSerializer,
    UserSerializer,
    UserWriteSerializer,
)


class LoginView(TokenObtainPairView):
    """Login endpoint enforcing the account-lockout policy via LoginSerializer."""

    serializer_class = LoginSerializer


class RefreshView(TokenRefreshView):
    """Refresh endpoint enforcing the password-change policy via PasswordAwareTokenRefreshSerializer."""

    serializer_class = PasswordAwareTokenRefreshSerializer


class ChangePasswordView(APIView):
    """Self-service password change. Succeeding invalidates every outstanding
    session/token for the user, including the one used to make this request."""

    def post(self, request: Request) -> Response:
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password updated. Please log in again."})


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
