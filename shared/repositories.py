from typing import Generic, Optional, TypeVar

from django.db.models import Model, QuerySet

ModelT = TypeVar("ModelT", bound=Model)


class BaseRepository(Generic[ModelT]):
    """Common read/delete operations shared by every module's repository.

    Module repositories subclass this and set `model`, adding whatever
    domain-specific queries they need on top.
    """

    model: type[ModelT]

    def all(self) -> "QuerySet[ModelT]":
        return self.model.objects.all()

    def get_by_id(self, pk) -> Optional[ModelT]:
        return self.model.objects.filter(pk=pk).first()

    def delete(self, instance: ModelT) -> None:
        instance.delete()
