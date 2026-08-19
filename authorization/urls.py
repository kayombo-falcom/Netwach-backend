from django.urls import path

from authorization.views import RoleDetailView, RoleListCreateView, RolePermissionsView

urlpatterns = [
    # Must precede '<str:name>/' — otherwise "permissions" would be swallowed as a role name.
    path("permissions/", RolePermissionsView.as_view(), name="role-permissions"),
    path("", RoleListCreateView.as_view(), name="role-list"),
    path("<str:name>/", RoleDetailView.as_view(), name="role-detail"),
]
