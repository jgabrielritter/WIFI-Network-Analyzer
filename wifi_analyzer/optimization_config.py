from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OptimizationConfig:
    """Centralized thresholds for scan-based optimization guidance."""

    strong_rssi_dbm: int = -57
    usable_rssi_dbm: int = -67
    weak_rssi_dbm: int = -75
    dead_zone_rssi_dbm: int = -82
    likely_dead_zone_absent_ratio: float = 0.75
    min_scans_for_moderate_confidence: int = 2
    min_scans_for_strong_confidence: int = 4
    high_congestion_channels: int = 2
    weak_zone_priority_boost: int = 25
    dead_zone_priority_boost: int = 40
    missing_target_priority_boost: int = 30
    high_congestion_priority_boost: int = 10
    lower_band_only_priority_boost: int = 10
    significant_signal_gap_dbm: int = 14
    heuristics_disclaimer: str = (
        "Optimization guidance is based on observed scan data and heuristics. "
        "It is advisory and not a guaranteed performance prediction."
    )


DEFAULT_OPTIMIZATION_CONFIG = OptimizationConfig()
