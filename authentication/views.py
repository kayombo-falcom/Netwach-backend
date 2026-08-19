from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.serializers import (
    ChangePasswordRequestSerializer,
    LoginRequestSerializer,
    RefreshRequestSerializer,
)
from authentication.services import AuthenticationService


class LoginView(APIView):
    """Login endpoint enforcing the account-lockout policy via AuthenticationService."""

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = LoginRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tokens = AuthenticationService().login(**serializer.validated_data)
        return Response(tokens)


class RefreshView(APIView):
    """Refresh endpoint enforcing the password-change policy via AuthenticationService."""

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = RefreshRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tokens = AuthenticationService().refresh(serializer.validated_data["refresh"])
        return Response(tokens)


class ChangePasswordView(APIView):
    """Self-service password change. Succeeding invalidates every outstanding
    session/token for the user, including the one used to make this request."""

    def post(self, request: Request) -> Response:
        serializer = ChangePasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        AuthenticationService().change_password(request.user, **serializer.validated_data)
        return Response({"detail": "Password updated. Please log in again."})


class MeView(APIView):
    """Confirms the bearer token is valid and its user still exists and is active.

    IdleTimeoutJWTAuthentication already re-fetches the user from the database per
    request and rejects the token if the user was deleted or deactivated since it
    was issued.
    """

    def get(self, request: Request) -> Response:
        user = request.user
        return Response({"id": user.id, "email": user.email, "name": user.name, "role": user.role})
