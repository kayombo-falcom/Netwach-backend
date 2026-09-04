import json
import urllib.request

from network.isp_brands import brand_name_for_isp

CLOUDFLARE_META_URL = "https://speed.cloudflare.com/meta"


def get_network_meta() -> dict:
    # Cloudflare's meta endpoint rejects requests that look like bare bot
    # traffic (default User-Agent, or a cross-origin Origin header). A
    # browser UA + same-site Referer is what its own speed test page sends.
    req = urllib.request.Request(
        CLOUDFLARE_META_URL,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Referer": "https://speed.cloudflare.com/",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf8"))

    return {
        "isp": brand_name_for_isp(data.get("asn"), data.get("asOrganization")),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "publicIp": data.get("clientIp"),
    }
