from network.platform_linux import measure_packet_loss

# Cloudflare's public resolver — same provider as the rest of the speed
# test, and reliable enough that any loss reported is our own path's fault.
TARGET = "1.1.1.1"

# Windows paces `ping` sends about 1s apart regardless of -w, so 10 pings is
# already a ~10s measurement — enough for 10%-granularity without stretching
# what's meant to be a quick speed test into a much longer wait.
PING_COUNT = 10
PING_TIMEOUT_MS = 1000


def measure_connection_packet_loss() -> dict | None:
    return measure_packet_loss(TARGET, PING_COUNT, PING_TIMEOUT_MS)
