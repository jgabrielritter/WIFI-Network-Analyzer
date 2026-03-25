from __future__ import annotations

from .scan_history import ScanSnapshot
from .scan_comparison import build_scan_profile, compare_ssid_across_snapshots


def build_environment_score_trend(snapshots: list[ScanSnapshot]) -> list[tuple[str, int, str]]:
    trend: list[tuple[str, int, str]] = []
    for snapshot in sorted(snapshots, key=lambda item: item.created_at):
        profile = build_scan_profile(snapshot)
        trend.append((snapshot.created_at, profile.environment_score, profile.environment_label))
    return trend


def build_ssid_signal_trend(snapshots: list[ScanSnapshot], target_ssid: str) -> list[tuple[str, int | None, str]]:
    observations = compare_ssid_across_snapshots(snapshots, target_ssid=target_ssid)
    return [(item.created_at, item.strongest_rssi_dbm, item.scan_label) for item in observations]
