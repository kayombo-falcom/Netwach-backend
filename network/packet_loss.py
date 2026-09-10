from network.platform_linux import measure_packet_loss

# Cloudflare's public resolver — reliable enough that any loss reported is our own path's fault.
TARGET = "1.1.1.1"

# ping's default 1s interval makes 10 pings a ~10s measurement — enough for 10%-granularity without a long wait.
PING_COUNT = 10
PING_TIMEOUT_MS = 1000


def measure_connection_packet_loss() -> dict | None:
    return measure_packet_loss(TARGET, PING_COUNT, PING_TIMEOUT_MS)
