from django.contrib import admin

from devices.models import DeviceActivity, NetworkDevice

admin.site.register(NetworkDevice)
admin.site.register(DeviceActivity)
