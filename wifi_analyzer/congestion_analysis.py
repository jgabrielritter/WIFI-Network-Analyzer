from __future__ import annotations

from dataclasses import dataclass

from .analytics_config import AnalyticsConfig
from .dashboard_logic import normalize_band_badge
from .wifi_models import WiFiNetworkRecord


@dataclass(frozen=True)
class ChannelCongestion:
    channel: int
    band: str
    network_count: int
    weighted_score: float
    label: str


def signal_weight(rssi_dbm: int | None) -> float:
    if rssi_dbm is None:
        return 0.6
    if rssi_dbm >= -55:
        return 1.0
    if rssi_dbm >= -67:
        return 0.8
    if rssi_dbm >= -75:
        return 0.55
    if rssi_dbm >= -85:
        return 0.3
    return 0.15


def _label_for(score: float, config: AnalyticsConfig) -> str:
    if score <= config.congestion_thresholds.low_max:
        return "Low"
    if score <= config.congestion_thresholds.moderate_max:
        return "Moderate"
    return "High"


def analyze_channel_congestion(networks: list[WiFiNetworkRecord], config: AnalyticsConfig) -> list[ChannelCongestion]:
    buckets: dict[tuple[str, int], list[WiFiNetworkRecord]] = {}
    for network in networks:
        if network.channel is None:
            continue
        band = normalize_band_badge(network.band)
        buckets.setdefault((band, network.channel), []).append(network)

    results: list[ChannelCongestion] = []
    for (band, channel), members in buckets.items():
        weighted = float(len(members))
        if config.weighted_congestion_enabled:
            weighted = sum(signal_weight(n.rssi_dbm) for n in members)
        results.append(
            ChannelCongestion(
                channel=channel,
                band=band,
                network_count=len(members),
                weighted_score=round(weighted, 2),
                label=_label_for(weighted, config),
            )
        )

    return sorted(results, key=lambda row: (row.weighted_score, row.network_count), reverse=True)
