from django.contrib import admin

from authorization.models import Role, RolePermission

admin.site.register(Role)
admin.site.register(RolePermission)
