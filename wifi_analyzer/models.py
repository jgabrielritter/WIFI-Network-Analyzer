from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    display_name: str
    ipv4: str | None = None
    netmask: str | None = None
    likely_wireless: bool = False
    confidence: str = "unknown"
    reason: str = ""


@dataclass(frozen=True)
class DeviceRecord:
    ip: str
    mac: str
    vendor: str


@dataclass(frozen=True)
class PacketRecord:
    timestamp: str
    src: str
    dst: str
    protocol: str


@dataclass
class UIEvent:
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
