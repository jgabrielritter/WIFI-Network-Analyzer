from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone

from .wifi_models import WiFiNetworkRecord, WiFiScanResult


@dataclass(frozen=True)
class ScanContext:
    scan_label: str | None = None
    room_name: str | None = None
    location_name: str | None = None
    floor_name: str | None = None
    building_zone: str | None = None
    time_of_day_label: str | None = None
    notes: str | None = None

    def to_display_label(self) -> str:
        parts = [self.scan_label, self.room_name, self.location_name, self.time_of_day_label]
        compact = [item.strip() for item in parts if item and item.strip()]
        return " | ".join(compact) if compact else "Unlabeled scan"

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


@dataclass(frozen=True)
class ScanSnapshot:
    snapshot_id: str
    created_at: str
    source: str
    interface_name: str | None
    warning: str | None
    context: ScanContext = field(default_factory=ScanContext)
    networks: list[WiFiNetworkRecord] = field(default_factory=list)


class ScanHistoryStore:
    def __init__(self, max_entries: int = 20) -> None:
        self.max_entries = max_entries
        self._items: list[ScanSnapshot] = []

    def add_result(self, result: WiFiScanResult, context: ScanContext | None = None) -> ScanSnapshot:
        created_at = datetime.now(timezone.utc).isoformat()
        snapshot = ScanSnapshot(
            snapshot_id=created_at,
            created_at=created_at,
            source=result.source,
            interface_name=result.interface_name,
            warning=result.warning,
            context=context or ScanContext(),
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

    def update_context(self, snapshot_id: str, context: ScanContext) -> ScanSnapshot | None:
        for idx, item in enumerate(self._items):
            if item.snapshot_id == snapshot_id:
                updated = replace(item, context=context)
                self._items[idx] = updated
                return updated
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
