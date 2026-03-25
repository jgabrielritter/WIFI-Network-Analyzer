from __future__ import annotations

from dataclasses import dataclass

from .grouping import SSIDGroupSummary
from .wifi_models import WiFiNetworkRecord


@dataclass(frozen=True)
class AccessPointRecommendation:
    ssid_group: str
    recommended_bssid: str | None
    recommendation_text: str
    tied_bssids: list[str]


def rank_group_members(group: SSIDGroupSummary) -> list[WiFiNetworkRecord]:
    return sorted(
        group.networks,
        key=lambda n: (n.rssi_dbm if n.rssi_dbm is not None else -1000, n.signal_percent if n.signal_percent is not None else -1),
        reverse=True,
    )


def recommend_strongest_access_point(group: SSIDGroupSummary, near_tie_dbm: int) -> AccessPointRecommendation:
    ranked = rank_group_members(group)
    if not ranked:
        return AccessPointRecommendation(
            ssid_group=group.group_key,
            recommended_bssid=None,
            recommendation_text="No observable access points for this SSID group.",
            tied_bssids=[],
        )

    top = ranked[0]
    top_rssi = top.rssi_dbm if top.rssi_dbm is not None else -1000
    tied = [n.bssid for n in ranked if n.bssid and (n.rssi_dbm if n.rssi_dbm is not None else -1000) >= top_rssi - near_tie_dbm]

    if len(tied) > 1:
        text = (
            f"Likely best access point based on current scan: {top.bssid or 'N/A'} ({top.signal_display}). "
            f"{len(tied)} APs are within {near_tie_dbm} dBm, so this is a near-tie."
        )
    else:
        text = f"Strongest observed access point for this SSID group: {top.bssid or 'N/A'} ({top.signal_display})."

    return AccessPointRecommendation(
        ssid_group=group.group_key,
        recommended_bssid=top.bssid,
        recommendation_text=text,
        tied_bssids=[b for b in tied if b],
    )
