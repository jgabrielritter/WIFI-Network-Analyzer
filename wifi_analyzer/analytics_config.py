from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CongestionThresholds:
    low_max: float = 2.5
    moderate_max: float = 5.0


@dataclass(frozen=True)
class EnvironmentLabelThresholds:
    excellent_min: int = 85
    good_min: int = 70
    fair_min: int = 50
    poor_min: int = 30


@dataclass(frozen=True)
class EnvironmentWeights:
    density_penalty: float = 2.0
    strong_overlap_penalty: float = 3.0
    crowded_24_penalty: float = 2.0
    open_security_penalty: float = 2.0
    mixed_security_penalty: float = 4.0
    clean_high_band_bonus: float = 1.5


@dataclass(frozen=True)
class AnalyticsConfig:
    weighted_congestion_enabled: bool = True
    hidden_ssid_group_name: str = "<Hidden SSID Group>"
    near_tie_dbm: int = 3
    strong_signal_cutoff_dbm: int = -67
    history_window_scans: int = 5
    congestion_thresholds: CongestionThresholds = field(default_factory=CongestionThresholds)
    environment_labels: EnvironmentLabelThresholds = field(default_factory=EnvironmentLabelThresholds)
    environment_weights: EnvironmentWeights = field(default_factory=EnvironmentWeights)


DEFAULT_ANALYTICS_CONFIG = AnalyticsConfig()
