from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanProfile:
    snapshot_id: str
    created_at: str
    scan_label: str
    room_name: str | None
    location_name: str | None
    time_of_day_label: str | None
    total_networks: int
    open_networks: int
    secured_networks: int
    duplicate_ssid_groups: int
    band_distribution: dict[str, int]
    crowded_channels: list[str]
    environment_score: int
    environment_label: str
    strongest_by_ssid: dict[str, int]
    strongest_bssid_by_ssid: dict[str, str]


@dataclass(frozen=True)
class SSIDScanObservation:
    snapshot_id: str
    created_at: str
    scan_label: str
    present: bool
    strongest_rssi_dbm: int | None
    strongest_bssid: str | None
    channel: int | None
    band: str | None
    security_mode: str | None


@dataclass(frozen=True)
class ScanComparisonResult:
    left: ScanProfile
    right: ScanProfile
    deltas: dict[str, int | str | None]
    ssid_delta: dict[str, int | str | None] = field(default_factory=dict)
    channel_delta: dict[str, str | int | None] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    disclaimer: str = ""
