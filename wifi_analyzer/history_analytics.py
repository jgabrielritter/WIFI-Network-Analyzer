from __future__ import annotations

from dataclasses import dataclass

from .scan_history import ScanSnapshot


@dataclass(frozen=True)
class HistoryInsight:
    summary: str
    appeared_bssids: int
    disappeared_bssids: int


def compare_snapshots(latest: ScanSnapshot | None, previous: ScanSnapshot | None) -> HistoryInsight | None:
    if latest is None or previous is None:
        return None

    latest_bssids = {n.bssid for n in latest.networks if n.bssid}
    prev_bssids = {n.bssid for n in previous.networks if n.bssid}

    appeared = len(latest_bssids - prev_bssids)
    disappeared = len(prev_bssids - latest_bssids)
    return HistoryInsight(
        summary=(
            f"Compared with {previous.created_at}: {appeared} BSSID(s) appeared, "
            f"{disappeared} disappeared in latest snapshot."
        ),
        appeared_bssids=appeared,
        disappeared_bssids=disappeared,
    )
