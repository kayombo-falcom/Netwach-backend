from rest_framework.exceptions import ValidationError

from authorization.repositories import RoleRepository
from users.models import User
from users.repositories import UserRepository


class UserService:
    """Owns user creation/update, including the "role must be real" invariant —
    the one place `users` reaches into `authorization`.
    """

    def __init__(self, user_repo: UserRepository | None = None, role_repo: RoleRepository | None = None):
        self.users = user_repo or UserRepository()
        self.roles = role_repo or RoleRepository()

    def create_user(self, *, name: str, email: str, role: str, password: str, status: str = "active") -> User:
        self._ensure_role_exists(role)
        return self.users.create(name=name, email=email, role=role, password=password, is_active=status == "active")

    def update_user(self, user: User, **changes) -> User:
        if "role" in changes:
            self._ensure_role_exists(changes["role"])
        if "status" in changes:
            user.is_active = changes.pop("status") == "active"
        for attr, value in changes.items():
            setattr(user, attr, value)
        return self.users.save(user)

    def _ensure_role_exists(self, role_name: str) -> None:
        if not self.roles.exists(role_name):
            raise ValidationError({"role": "Not a recognized role."})
