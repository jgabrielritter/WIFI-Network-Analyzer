from __future__ import annotations

from dataclasses import dataclass

from .analytics_config import AnalyticsConfig, DEFAULT_ANALYTICS_CONFIG
from .congestion_analysis import ChannelCongestion, analyze_channel_congestion
from .environment_scoring import EnvironmentScore, score_environment
from .grouping import SSIDGroupSummary, group_by_ssid
from .history_analytics import HistoryInsight, compare_snapshots
from .recommendation_engine import AccessPointRecommendation, rank_group_members, recommend_strongest_access_point
from .scan_history import ScanSnapshot
from .wifi_models import WiFiNetworkRecord


@dataclass(frozen=True)
class WiFiAnalyticsReport:
    groups: list[SSIDGroupSummary]
    recommendations: dict[str, AccessPointRecommendation]
    channel_congestion: list[ChannelCongestion]
    environment: EnvironmentScore
    insights: list[str]
    network_rank_by_bssid: dict[str, int]
    strongest_bssid_by_group: dict[str, str]
    history_insight: HistoryInsight | None


class WiFiAnalyticsEngine:
    def __init__(self, config: AnalyticsConfig = DEFAULT_ANALYTICS_CONFIG) -> None:
        self.config = config

    def build_report(
        self,
        networks: list[WiFiNetworkRecord],
        latest_snapshot: ScanSnapshot | None = None,
        previous_snapshot: ScanSnapshot | None = None,
    ) -> WiFiAnalyticsReport:
        groups = group_by_ssid(networks, hidden_group_name=self.config.hidden_ssid_group_name)
        recommendations = {
            group.group_key: recommend_strongest_access_point(group, near_tie_dbm=self.config.near_tie_dbm) for group in groups
        }
        channel_congestion = analyze_channel_congestion(networks, config=self.config)
        environment = score_environment(networks, channel_congestion=channel_congestion, groups=groups, config=self.config)

        network_rank_by_bssid: dict[str, int] = {}
        strongest_bssid_by_group: dict[str, str] = {}
        insights: list[str] = []

        for group in groups:
            ranked = rank_group_members(group)
            for idx, network in enumerate(ranked, start=1):
                if network.bssid:
                    network_rank_by_bssid[network.bssid] = idx
            if ranked and ranked[0].bssid:
                strongest_bssid_by_group[group.group_key] = ranked[0].bssid

        if channel_congestion:
            top = channel_congestion[0]
            insights.append(
                f"Channel {top.channel} ({top.band}) appears {top.label.lower()} congestion with {top.network_count} observed networks."
            )

        if groups:
            largest = groups[0]
            insights.append(
                f"SSID group '{largest.ssid_display}' has {largest.access_point_count} observed AP(s); strongest is {largest.strongest_bssid or 'N/A'}."
            )

        insights.append(
            f"Environment quality is {environment.label} ({environment.score}/100) based on current observed scan data and heuristic scoring."
        )
        insights.extend(environment.reasons[:2])

        history = compare_snapshots(latest_snapshot, previous_snapshot)
        if history:
            insights.append(history.summary)

        return WiFiAnalyticsReport(
            groups=groups,
            recommendations=recommendations,
            channel_congestion=channel_congestion,
            environment=environment,
            insights=insights,
            network_rank_by_bssid=network_rank_by_bssid,
            strongest_bssid_by_group=strongest_bssid_by_group,
            history_insight=history,
        )


def group_key_for_network(network: WiFiNetworkRecord, hidden_group_name: str) -> str:
    if network.ssid and network.ssid.strip():
        return network.ssid.strip()
    return hidden_group_name
