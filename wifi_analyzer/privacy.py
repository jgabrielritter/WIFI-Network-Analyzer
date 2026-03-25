"""Utilities to mask sensitive endpoint details by default."""


def mask_ip(ip_addr: str) -> str:
    parts = ip_addr.split(".")
    if len(parts) != 4:
        return ip_addr
    return ".".join(parts[:3] + ["x"])


def mask_mac(mac_addr: str) -> str:
    normalized = mac_addr.replace("-", ":")
    parts = normalized.split(":")
    if len(parts) != 6:
        return mac_addr
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


def summarize_endpoint(src: str, dst: str, redact: bool = True) -> tuple[str, str]:
    if not redact:
        return src, dst
    return mask_ip(src), mask_ip(dst)
