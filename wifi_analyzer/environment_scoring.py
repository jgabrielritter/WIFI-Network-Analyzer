from __future__ import annotations

from dataclasses import dataclass

from .analytics_config import AnalyticsConfig
from .congestion_analysis import ChannelCongestion
from .grouping import SSIDGroupSummary
from .wifi_models import WiFiNetworkRecord


@dataclass(frozen=True)
class EnvironmentScore:
    score: int
    label: str
    reasons: list[str]


def _label(score: int, config: AnalyticsConfig) -> str:
    limits = config.environment_labels
    if score >= limits.excellent_min:
        return "Excellent"
    if score >= limits.good_min:
        return "Good"
    if score >= limits.fair_min:
        return "Fair"
    if score >= limits.poor_min:
        return "Poor"
    return "Congested"


def score_environment(
    networks: list[WiFiNetworkRecord],
    channel_congestion: list[ChannelCongestion],
    groups: list[SSIDGroupSummary],
    config: AnalyticsConfig,
) -> EnvironmentScore:
    if not networks:
        return EnvironmentScore(score=100, label="Excellent", reasons=["No nearby networks observed in this scan snapshot."])

    reasons: list[str] = []
    weights = config.environment_weights
    score = 100.0

    strong_overlap = len([n for n in networks if n.rssi_dbm is not None and n.rssi_dbm >= config.strong_signal_cutoff_dbm])
    score -= len(networks) * weights.density_penalty
    score -= strong_overlap * weights.strong_overlap_penalty

    crowded_24 = [c for c in channel_congestion if c.band == "2.4 GHz" and c.label == "High"]
    score -= len(crowded_24) * weights.crowded_24_penalty

    open_or_weak = len([n for n in networks if (n.security_mode or "").upper() in {"OPEN", "WEP"}])
    score -= open_or_weak * weights.open_security_penalty

    mixed_groups = len([g for g in groups if g.is_security_mixed])
    score -= mixed_groups * weights.mixed_security_penalty

    clean_high_band = any(c.band in {"5 GHz", "6 GHz"} and c.label == "Low" for c in channel_congestion)
    if clean_high_band:
        score += weights.clean_high_band_bonus

    if len(networks) > 15:
        reasons.append(f"Dense environment snapshot with {len(networks)} nearby networks.")
    if strong_overlap > 4:
        reasons.append(f"{strong_overlap} strong nearby networks may increase observed overlap.")
    if crowded_24:
        reasons.append("2.4 GHz appears crowded based on observed nearby networks.")
    if open_or_weak:
        reasons.append(f"{open_or_weak} nearby networks advertise open/weak security modes.")
    if clean_high_band:
        reasons.append("At least one higher band channel appears relatively clean in this scan.")

    bounded = max(0, min(100, int(round(score))))
    if not reasons:
        reasons.append("Moderate observed density with no extreme congestion indicators in this snapshot.")
    return EnvironmentScore(score=bounded, label=_label(bounded, config), reasons=reasons)
