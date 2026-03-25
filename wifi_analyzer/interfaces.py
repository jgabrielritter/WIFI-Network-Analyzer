"""Interface discovery and validation helpers."""

from __future__ import annotations

import ipaddress
from dataclasses import replace

from .netifaces_compat import netifaces

from .constants import (
    INTERFACE_EXCLUDE_KEYWORDS,
    INTERFACE_LAN_KEYWORDS,
    INTERFACE_WIRELESS_KEYWORDS,
)
from .models import InterfaceInfo


def _score_interface(name: str) -> tuple[int, bool, str]:
    lower = name.lower()
    if any(token in lower for token in INTERFACE_EXCLUDE_KEYWORDS):
        return -2, False, "virtual or excluded adapter pattern"
    if any(token in lower for token in INTERFACE_WIRELESS_KEYWORDS):
        return 3, True, "wireless name hint"
    if any(token in lower for token in INTERFACE_LAN_KEYWORDS):
        return 1, False, "wired/LAN name hint"
    return 0, False, "no strong naming signal"


def discover_interfaces() -> list[InterfaceInfo]:
    default_iface = netifaces.gateways().get("default", {}).get(netifaces.AF_INET, [None, None])[1]
    interfaces: list[InterfaceInfo] = []

    for name in netifaces.interfaces():
        score, likely_wireless, reason = _score_interface(name)
        iface_info = netifaces.ifaddresses(name).get(netifaces.AF_INET, [{}])
        ipv4 = iface_info[0].get("addr") if iface_info else None
        netmask = iface_info[0].get("netmask") if iface_info else None

        if not ipv4:
            continue

        confidence = "high" if score >= 3 else "medium" if score >= 1 else "low"
        marker = "Wi-Fi?" if likely_wireless else "LAN"
        display = f"{name} ({marker}, {confidence}, {ipv4})"
        if default_iface == name:
            display = f"{display} [default gateway]"

        interfaces.append(
            InterfaceInfo(
                name=name,
                display_name=display,
                ipv4=ipv4,
                netmask=netmask,
                likely_wireless=likely_wireless,
                confidence=confidence,
                reason=reason,
            )
        )

    interfaces.sort(key=lambda item: (item.name != default_iface, item.name))
    return interfaces


def resolve_interface_network(selected: InterfaceInfo) -> ipaddress.IPv4Network:
    if not selected.ipv4:
        raise RuntimeError(f"Interface '{selected.name}' has no IPv4 address.")
    if not selected.netmask:
        raise RuntimeError(f"Interface '{selected.name}' is missing a netmask.")
    return ipaddress.ip_interface(f"{selected.ipv4}/{selected.netmask}").network


def annotate_with_latest(selected: InterfaceInfo | None) -> InterfaceInfo:
    """Refresh the selected interface with the latest metadata."""
    if selected is None:
        raise RuntimeError("No interface selected.")
    for iface in discover_interfaces():
        if iface.name == selected.name:
            return iface
    return replace(selected, reason="not currently available")


def privilege_guidance() -> str:
    return (
        "Packet capture and ARP scans may require elevated permissions. "
        "On Linux/macOS run with sudo or grant capture capabilities; on Windows run as Administrator."
    )
