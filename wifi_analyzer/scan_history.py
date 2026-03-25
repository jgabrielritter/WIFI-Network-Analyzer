from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .wifi_models import WiFiNetworkRecord, WiFiScanResult


@dataclass(frozen=True)
class ScanSnapshot:
    snapshot_id: str
    created_at: str
    source: str
    interface_name: str | None
    warning: str | None
    networks: list[WiFiNetworkRecord] = field(default_factory=list)


class ScanHistoryStore:
    def __init__(self, max_entries: int = 20) -> None:
        self.max_entries = max_entries
        self._items: list[ScanSnapshot] = []

    def add_result(self, result: WiFiScanResult) -> ScanSnapshot:
        created_at = datetime.now(timezone.utc).isoformat()
        snapshot = ScanSnapshot(
            snapshot_id=created_at,
            created_at=created_at,
            source=result.source,
            interface_name=result.interface_name,
            warning=result.warning,
            networks=list(result.networks),
        )
        self._items.insert(0, snapshot)
        if len(self._items) > self.max_entries:
            self._items = self._items[: self.max_entries]
        return snapshot

    def list_snapshots(self) -> list[ScanSnapshot]:
        return list(self._items)

    def get(self, snapshot_id: str) -> ScanSnapshot | None:
        for item in self._items:
            if item.snapshot_id == snapshot_id:
                return item
        return None

    def compare_latest(self) -> dict[str, int] | None:
        if len(self._items) < 2:
            return None
        latest = self._items[0]
        previous = self._items[1]

        latest_bssids = {item.bssid for item in latest.networks if item.bssid}
        previous_bssids = {item.bssid for item in previous.networks if item.bssid}

        return {
            "new": len(latest_bssids - previous_bssids),
            "missing": len(previous_bssids - latest_bssids),
            "unchanged": len(latest_bssids & previous_bssids),
        }
