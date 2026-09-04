"""URL routes for API version 1. Included by netwatch_backend.urls under api/v1/."""
from django.urls import include, path

urlpatterns = [
    path('auth/', include('authentication.urls')),
    path('users/', include('users.urls')),
    path('roles/', include('authorization.urls')),
    path('devices/', include('devices.urls')),
    path('network/', include('network.urls')),
]
