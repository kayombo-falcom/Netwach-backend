"""ASN -> consumer brand name overrides.

IP geolocation providers report the ISP's legal/registry name (from ASN
WHOIS records), which is often outdated or unrecognizable — e.g. ASN 15399
resolves to "Wananchi Cable Tanzania" even though the retail brand on the
router and the bill is "Zuku". Add entries here as they come up; unknown
ASNs just fall back to the raw registry name.
"""

ISP_BRAND_BY_ASN = {
    15399: "Zuku",
}


def brand_name_for_isp(asn: int | None, registry_name: str | None) -> str | None:
    if asn is not None and asn in ISP_BRAND_BY_ASN:
        return ISP_BRAND_BY_ASN[asn]
    return registry_name
