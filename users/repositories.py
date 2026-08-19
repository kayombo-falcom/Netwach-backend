from shared.repositories import BaseRepository

from users.models import User


class UserRepository(BaseRepository[User]):
    model = User

    def list_all(self):
        return User.objects.all().order_by("name")

    def get_by_email(self, email: str) -> User | None:
        return User.objects.filter(email__iexact=email).first()

    def exists_with_role(self, role_name: str) -> bool:
        return User.objects.filter(role=role_name).exists()

    def reassign_role(self, old_role: str, new_role: str) -> None:
        User.objects.filter(role=old_role).update(role=new_role)

    def create(self, *, name: str, email: str, role: str, password: str, is_active: bool = True) -> User:
        return User.objects.create_user(email=email, password=password, name=name, role=role, is_active=is_active)

    def save(self, user: User, update_fields: list[str] | None = None) -> User:
        user.save(update_fields=update_fields)
        return user
