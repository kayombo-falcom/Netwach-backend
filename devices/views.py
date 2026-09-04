from rest_framework import generics, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from authorization.models import Permission
from authorization.permissions import HasPermission
from devices.models import NetworkDevice
from devices.serializers import DeviceDetectionSerializer, NetworkDeviceSerializer


class DeviceListView(generics.ListAPIView):
    queryset = NetworkDevice.objects.all()
    serializer_class = NetworkDeviceSerializer
    permission_classes = [HasPermission(Permission.DEVICES_VIEW)]


class DeviceDetectionView(APIView):
    """Persists an OS-detection result produced by the frontend's live scan
    engine. Upserts by MAC, so re-running detection on a known device updates
    its existing record instead of duplicating it."""

    permission_classes = [HasPermission(Permission.DEVICES_MANAGE)]

    def post(self, request: Request) -> Response:
        serializer = DeviceDetectionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = serializer.save()
        return Response(NetworkDeviceSerializer(device).data, status=status.HTTP_201_CREATED)
