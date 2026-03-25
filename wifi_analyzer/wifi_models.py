from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class WiFiNetworkRecord:
    ssid: str | None
    bssid: str | None
    rssi_dbm: int | None = None
    signal_percent: int | None = None
    channel: int | None = None
    frequency_mhz: int | None = None
    band: str = "Unknown"
    security_mode: str = "Unknown"
    encryption_details: str | None = None
    interface_name: str | None = None
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_hidden: bool = False
    raw_source: dict[str, Any] = field(default_factory=dict)

    @property
    def display_ssid(self) -> str:
        if self.ssid:
            return self.ssid
        return "<Hidden SSID>"

    @property
    def signal_quality_label(self) -> str:
        if self.rssi_dbm is not None:
            if self.rssi_dbm >= -55:
                return "Excellent"
            if self.rssi_dbm >= -67:
                return "Good"
            if self.rssi_dbm >= -75:
                return "Fair"
            return "Weak"

        if self.signal_percent is not None:
            if self.signal_percent >= 80:
                return "Excellent"
            if self.signal_percent >= 60:
                return "Good"
            if self.signal_percent >= 40:
                return "Fair"
            return "Weak"

        return "Unknown"

    @property
    def signal_display(self) -> str:
        parts: list[str] = []
        if self.rssi_dbm is not None:
            parts.append(f"{self.rssi_dbm} dBm")
        if self.signal_percent is not None:
            parts.append(f"{self.signal_percent}%")
        if not parts:
            parts.append("N/A")
        return f"{' / '.join(parts)} ({self.signal_quality_label})"


@dataclass(frozen=True)
class WiFiScanResult:
    networks: list[WiFiNetworkRecord]
    interface_name: str | None = None
    source: str = "unknown"
    warning: str | None = None
