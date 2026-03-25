from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean

from .comparison_models import ScanProfile
from .dashboard_logic import normalize_band_badge
from .optimization_config import OptimizationConfig
from .optimization_models import RoomCoverageSummary
from .scan_history import ScanSnapshot


def _room_label(snapshot: ScanSnapshot) -> str:
    return snapshot.context.room_name or snapshot.context.location_name or snapshot.context.scan_label or "Unlabeled area"


def _confidence_label(scans_count: int, consistency_ratio: float, config: OptimizationConfig) -> str:
    if scans_count >= config.min_scans_for_strong_confidence and consistency_ratio >= 0.7:
        return "Strong repeated evidence"
    if scans_count >= config.min_scans_for_moderate_confidence:
        return "Moderate evidence"
    return "Limited evidence"


def _classification(best_rssi: int | None, absent_ratio: float, lower_band_only: bool, config: OptimizationConfig) -> str:
    if best_rssi is None:
        if absent_ratio >= config.likely_dead_zone_absent_ratio:
            return "Likely dead zone"
        return "Target network not observed"

    if best_rssi >= config.strong_rssi_dbm:
        return "Strong coverage"
    if best_rssi >= config.usable_rssi_dbm:
        return "Usable coverage"
    if best_rssi >= config.weak_rssi_dbm:
        return "Weak coverage"
    if absent_ratio >= 0.5 or best_rssi <= config.dead_zone_rssi_dbm:
        return "Likely dead zone"
    if lower_band_only:
        return "Likely weak zone"
    return "Likely weak zone"


def summarize_room_coverage(
    snapshots: list[ScanSnapshot],
    target_ssid: str,
    profiles: dict[str, ScanProfile],
    config: OptimizationConfig,
) -> list[RoomCoverageSummary]:
    by_room: dict[str, list[ScanSnapshot]] = defaultdict(list)
    for snapshot in snapshots:
        by_room[_room_label(snapshot)].append(snapshot)

    room_env = {}
    for room, items in by_room.items():
        scores = [profiles[s.snapshot_id].environment_score for s in items if s.snapshot_id in profiles]
        room_env[room] = mean(scores) if scores else None

    avg_env = mean([score for score in room_env.values() if score is not None]) if room_env else None
    summaries: list[RoomCoverageSummary] = []

    for room, items in by_room.items():
        scans_count = len(items)
        strongest_network = None
        strongest_target_rssi = None
        target_bssid_counter: Counter[str] = Counter()
        target_band_counter: Counter[str] = Counter()
        target_absent_count = 0
        high_congestion = 0

        for snapshot in items:
            profile = profiles.get(snapshot.snapshot_id)
            if profile and len(profile.crowded_channels) >= config.high_congestion_channels:
                high_congestion += 1
            room_strongest = max(snapshot.networks, key=lambda n: n.rssi_dbm if n.rssi_dbm is not None else -999, default=None)
            if room_strongest and (
                strongest_network is None
                or ((room_strongest.rssi_dbm or -999) > (strongest_network.rssi_dbm or -999))
            ):
                strongest_network = room_strongest

            target_matches = [n for n in snapshot.networks if n.display_ssid == target_ssid]
            if not target_matches:
                target_absent_count += 1
                continue

            current_best = max(target_matches, key=lambda n: n.rssi_dbm if n.rssi_dbm is not None else -999)
            if current_best.rssi_dbm is not None and (
                strongest_target_rssi is None or current_best.rssi_dbm > strongest_target_rssi
            ):
                strongest_target_rssi = current_best.rssi_dbm
            for match in target_matches:
                if match.bssid:
                    target_bssid_counter[match.bssid] += 1
                target_band_counter[normalize_band_badge(match.band)] += 1

        present_count = scans_count - target_absent_count
        absent_ratio = (target_absent_count / scans_count) if scans_count else 1.0
        dominant_band = target_band_counter.most_common(1)[0][0] if target_band_counter else None
        lower_band_only = bool(target_band_counter) and set(target_band_counter.keys()).issubset({"2.4 GHz"})
        classification = _classification(strongest_target_rssi, absent_ratio, lower_band_only, config)

        consistency_ratio = max(absent_ratio, (present_count / scans_count) if scans_count else 0.0)
        confidence = _confidence_label(scans_count, consistency_ratio, config)

        env_score = room_env.get(room)
        env_label = "Unknown"
        if env_score is not None and avg_env is not None:
            if env_score >= avg_env + 5:
                env_label = "Better than average"
            elif env_score <= avg_env - 5:
                env_label = "Worse than average"
            else:
                env_label = "Near average"

        evidence = [
            f"{present_count}/{scans_count} scans observed target SSID." if scans_count else "No scans available.",
        ]
        if strongest_target_rssi is not None:
            evidence.append(f"Strongest observed target RSSI: {strongest_target_rssi} dBm.")
        if lower_band_only:
            evidence.append("Target SSID was only observed on 2.4 GHz in this area.")
        if high_congestion:
            evidence.append(f"{high_congestion} scans in this area showed higher channel crowding.")

        summaries.append(
            RoomCoverageSummary(
                room_name=room,
                scans_count=scans_count,
                strongest_observed_ssid=strongest_network.display_ssid if strongest_network else None,
                strongest_observed_bssid=strongest_network.bssid if strongest_network else None,
                strongest_target_rssi_dbm=strongest_target_rssi,
                dominant_target_band=dominant_band,
                multiple_target_bssids_visible=len(target_bssid_counter) > 1,
                target_absent_count=target_absent_count,
                target_present_count=present_count,
                high_congestion_observations=high_congestion,
                avg_environment_score=env_score,
                environment_relative_label=env_label,
                classification=classification,
                confidence=confidence,
                evidence=evidence,
            )
        )

    return sorted(
        summaries,
        key=lambda item: (item.strongest_target_rssi_dbm if item.strongest_target_rssi_dbm is not None else -999),
        reverse=True,
    )
