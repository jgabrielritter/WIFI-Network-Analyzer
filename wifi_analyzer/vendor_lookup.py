"""Vendor lookup utilities for MAC addresses."""

FALLBACK_VENDOR_MAP = {
    "000C29": "VMware",
    "0050F2": "Microsoft",
    "00163E": "HP",
    "3C5A37": "Google",
    "BC305B": "Apple",
}


def get_vendor(mac_address: str) -> str:
    try:
        from scapy.utils import oui_resolve

        vendor = oui_resolve(mac_address)
        if vendor:
            return vendor
    except Exception:
        pass

    try:
        normalized_mac = mac_address.replace("-", ":").upper()
        mac_prefix = normalized_mac.replace(":", "")[:6]
        return FALLBACK_VENDOR_MAP.get(mac_prefix, "Unknown")
    except Exception:
        return "Unknown"
