"""ASN -> consumer brand name overrides: IP geolocation gives the ISP's legal/registry name, which is often unrecognizable (e.g. ASN 15399 is "Wananchi Cable Tanzania", branded "Zuku"). Add entries as they come up; unknown ASNs fall back to the registry name."""

ISP_BRAND_BY_ASN = {
    15399: "Zuku",
}


def brand_name_for_isp(asn: int | None, registry_name: str | None) -> str | None:
    if asn is not None and asn in ISP_BRAND_BY_ASN:
        return ISP_BRAND_BY_ASN[asn]
    return registry_name
