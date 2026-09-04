from django.urls import path

from devices.views import DeviceDetectionView, DeviceListView

urlpatterns = [
    # Must precede '<str:mac>/'-style routes if any are added later — same
    # reasoning as authorization's 'permissions/' vs '<str:name>/'.
    path("detection/", DeviceDetectionView.as_view(), name="device-detection"),
    path("", DeviceListView.as_view(), name="device-list"),
]
