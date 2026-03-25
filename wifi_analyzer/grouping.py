from __future__ import annotations

from dataclasses import dataclass

from .dashboard_logic import normalize_band_badge, normalize_security_chip
from .wifi_models import WiFiNetworkRecord


@dataclass(frozen=True)
class SSIDGroupSummary:
    group_key: str
    ssid_display: str
    is_hidden_group: bool
    networks: list[WiFiNetworkRecord]
    access_point_count: int
    strongest_bssid: str | None
    strongest_signal_dbm: int | None
    strongest_quality_label: str
    channels: list[int]
    bands: list[str]
    security_modes: list[str]
    is_security_mixed: bool


def _group_key_for(network: WiFiNetworkRecord, hidden_group_name: str) -> str:
    if network.ssid and network.ssid.strip():
        return network.ssid.strip()
    return hidden_group_name


def group_by_ssid(networks: list[WiFiNetworkRecord], hidden_group_name: str) -> list[SSIDGroupSummary]:
    grouped: dict[str, list[WiFiNetworkRecord]] = {}
    for network in networks:
        key = _group_key_for(network, hidden_group_name=hidden_group_name)
        grouped.setdefault(key, []).append(network)

    summaries: list[SSIDGroupSummary] = []
    for key, members in grouped.items():
        sorted_members = sorted(
            members,
            key=lambda n: (n.rssi_dbm if n.rssi_dbm is not None else -1000, n.signal_percent if n.signal_percent is not None else -1),
            reverse=True,
        )
        strongest = sorted_members[0] if sorted_members else None
        channels = sorted({n.channel for n in members if n.channel is not None})
        bands = sorted({normalize_band_badge(n.band) for n in members})
        security = sorted({normalize_security_chip(n.security_mode) for n in members})
        summaries.append(
            SSIDGroupSummary(
                group_key=key,
                ssid_display=key,
                is_hidden_group=all(n.is_hidden or not n.ssid for n in members),
                networks=sorted_members,
                access_point_count=len(members),
                strongest_bssid=strongest.bssid if strongest else None,
                strongest_signal_dbm=strongest.rssi_dbm if strongest else None,
                strongest_quality_label=strongest.signal_quality_label if strongest else "Unknown",
                channels=channels,
                bands=bands,
                security_modes=security,
                is_security_mixed=len(security) > 1,
            )
        )

    return sorted(summaries, key=lambda item: (item.access_point_count, item.strongest_signal_dbm or -1000), reverse=True)
