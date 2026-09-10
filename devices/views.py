from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from authorization.models import Permission
from authorization.permissions import HasPermission
from devices.models import NetworkDevice
from devices.serializers import DeviceActivitySerializer, DeviceDetectionSerializer, NetworkDeviceSerializer
from devices.services import DeviceService


class DeviceListView(generics.ListAPIView):
    queryset = NetworkDevice.objects.all()
    serializer_class = NetworkDeviceSerializer
    permission_classes = [HasPermission(Permission.DEVICES_VIEW)]


class DeviceDetectionView(APIView):
    """Persists an OS-detection result from the frontend's live scan; upserts by MAC so re-running detection updates the existing record."""

    permission_classes = [HasPermission(Permission.DEVICES_MANAGE)]

    def post(self, request: Request) -> Response:
        serializer = DeviceDetectionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = serializer.save()
        return Response(NetworkDeviceSerializer(device).data, status=status.HTTP_201_CREATED)


class DeviceActivityListView(generics.ListAPIView):
    """A device's recent activity feed, most recent first; 404s for a MAC never persisted rather than returning an empty list."""

    serializer_class = DeviceActivitySerializer
    permission_classes = [HasPermission(Permission.DEVICES_VIEW)]

    def get_queryset(self):
        device = get_object_or_404(NetworkDevice, mac=self.kwargs["mac"].lower())
        return DeviceService().list_activity(device)
