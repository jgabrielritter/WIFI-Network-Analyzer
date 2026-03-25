from __future__ import annotations

from collections import Counter

from .comparison_config import ComparisonConfig, DEFAULT_COMPARISON_CONFIG
from .comparison_models import SSIDScanObservation, ScanComparisonResult, ScanProfile
from .dashboard_logic import normalize_band_badge, normalize_security_chip
from .scan_history import ScanSnapshot
from .wifi_analytics import WiFiAnalyticsEngine


def build_scan_profile(snapshot: ScanSnapshot, engine: WiFiAnalyticsEngine | None = None) -> ScanProfile:
    analytics_engine = engine or WiFiAnalyticsEngine()
    report = analytics_engine.build_report(snapshot.networks)

    strongest_by_ssid: dict[str, int] = {}
    strongest_bssid_by_ssid: dict[str, str] = {}
    open_count = 0
    band_distribution = {"2.4 GHz": 0, "5 GHz": 0, "6 GHz": 0, "Unknown": 0}

    for network in snapshot.networks:
        ssid = network.display_ssid
        band = normalize_band_badge(network.band)
        band_distribution[band] = band_distribution.get(band, 0) + 1
        if normalize_security_chip(network.security_mode) == "Open":
            open_count += 1
        if network.rssi_dbm is None:
            continue
        prev = strongest_by_ssid.get(ssid)
        if prev is None or network.rssi_dbm > prev:
            strongest_by_ssid[ssid] = network.rssi_dbm
            if network.bssid:
                strongest_bssid_by_ssid[ssid] = network.bssid

    return ScanProfile(
        snapshot_id=snapshot.snapshot_id,
        created_at=snapshot.created_at,
        scan_label=snapshot.context.to_display_label(),
        room_name=snapshot.context.room_name,
        location_name=snapshot.context.location_name,
        time_of_day_label=snapshot.context.time_of_day_label,
        total_networks=len(snapshot.networks),
        open_networks=open_count,
        secured_networks=max(0, len(snapshot.networks) - open_count),
        duplicate_ssid_groups=sum(1 for grp in report.groups if grp.access_point_count > 1),
        band_distribution=band_distribution,
        crowded_channels=[f"CH {c.channel} {c.band}" for c in report.channel_congestion if c.label in {"Moderate", "High"}],
        environment_score=report.environment.score,
        environment_label=report.environment.label,
        strongest_by_ssid=strongest_by_ssid,
        strongest_bssid_by_ssid=strongest_bssid_by_ssid,
    )


def compare_snapshots(
    left_snapshot: ScanSnapshot,
    right_snapshot: ScanSnapshot,
    target_ssid: str | None = None,
    config: ComparisonConfig = DEFAULT_COMPARISON_CONFIG,
) -> ScanComparisonResult:
    left = build_scan_profile(left_snapshot)
    right = build_scan_profile(right_snapshot)

    deltas: dict[str, int | str | None] = {
        "network_count_delta": right.total_networks - left.total_networks,
        "open_network_delta": right.open_networks - left.open_networks,
        "environment_score_delta": right.environment_score - left.environment_score,
        "duplicate_group_delta": right.duplicate_ssid_groups - left.duplicate_ssid_groups,
    }
    findings: list[str] = []

    env_delta = int(deltas["environment_score_delta"] or 0)
    if abs(env_delta) >= config.thresholds.significant_environment_delta:
        direction = "higher" if env_delta > 0 else "lower"
        findings.append(
            f"Observed environment score is {direction} in '{right.scan_label}' than '{left.scan_label}' by {abs(env_delta)} points."
        )

    channel_shift = sorted(set(right.crowded_channels) - set(left.crowded_channels))
    if channel_shift:
        findings.append(
            f"Channels appearing more crowded in '{right.scan_label}': {', '.join(channel_shift[:4])}."
        )

    ssid_delta: dict[str, int | str | None] = {}
    if target_ssid:
        left_rssi = left.strongest_by_ssid.get(target_ssid)
        right_rssi = right.strongest_by_ssid.get(target_ssid)
        if left_rssi is not None and right_rssi is not None:
            diff = right_rssi - left_rssi
            ssid_delta["rssi_delta_dbm"] = diff
            if abs(diff) >= config.thresholds.meaningful_rssi_delta_dbm:
                stronger = right.scan_label if diff > 0 else left.scan_label
                findings.append(
                    f"{target_ssid} is stronger in '{stronger}' by {abs(diff)} dB (observed RSSI snapshot difference)."
                )
        else:
            ssid_delta["rssi_delta_dbm"] = None
            ssid_delta["note"] = "SSID missing in one compared snapshot"

        left_bssid = left.strongest_bssid_by_ssid.get(target_ssid)
        right_bssid = right.strongest_bssid_by_ssid.get(target_ssid)
        ssid_delta["left_strongest_bssid"] = left_bssid
        ssid_delta["right_strongest_bssid"] = right_bssid
        if left_bssid and right_bssid and left_bssid != right_bssid:
            findings.append(f"{target_ssid} strongest observed BSSID differs between compared scans.")

    channel_delta = {
        "left_crowded_count": len(left.crowded_channels),
        "right_crowded_count": len(right.crowded_channels),
        "newly_crowded": ", ".join(channel_shift[:5]) if channel_shift else "None",
    }

    return ScanComparisonResult(
        left=left,
        right=right,
        deltas=deltas,
        ssid_delta=ssid_delta,
        channel_delta=channel_delta,
        findings=findings,
        disclaimer=config.heuristics_disclaimer,
    )


def compare_ssid_across_snapshots(snapshots: list[ScanSnapshot], target_ssid: str) -> list[SSIDScanObservation]:
    observations: list[SSIDScanObservation] = []
    for snapshot in snapshots:
        matches = [n for n in snapshot.networks if n.display_ssid == target_ssid]
        strongest = max(matches, key=lambda n: n.rssi_dbm if n.rssi_dbm is not None else -999, default=None)
        observations.append(
            SSIDScanObservation(
                snapshot_id=snapshot.snapshot_id,
                created_at=snapshot.created_at,
                scan_label=snapshot.context.to_display_label(),
                present=bool(matches),
                strongest_rssi_dbm=strongest.rssi_dbm if strongest else None,
                strongest_bssid=strongest.bssid if strongest else None,
                channel=strongest.channel if strongest else None,
                band=normalize_band_badge(strongest.band) if strongest else None,
                security_mode=normalize_security_chip(strongest.security_mode) if strongest else None,
            )
        )
    return observations


def summarize_channel_trends(snapshots: list[ScanSnapshot]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for snapshot in snapshots:
        for network in snapshot.networks:
            if network.channel is None:
                continue
            counts[f"CH {network.channel} {normalize_band_badge(network.band)}"] += 1
    return dict(counts.most_common())
