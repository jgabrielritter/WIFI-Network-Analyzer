from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ComparisonThresholds:
    meaningful_rssi_delta_dbm: int = 6
    significant_environment_delta: int = 10
    strong_competitor_dbm: int = -67
    crowded_channel_count: int = 4
    trend_min_points: int = 3


@dataclass(frozen=True)
class ComparisonConfig:
    thresholds: ComparisonThresholds = field(default_factory=ComparisonThresholds)
    heuristics_disclaimer: str = (
        "Comparisons are based on observed scan snapshots and heuristic analytics; they do not directly measure "
        "throughput, latency, roaming quality, or airtime utilization."
    )


DEFAULT_COMPARISON_CONFIG = ComparisonConfig()
