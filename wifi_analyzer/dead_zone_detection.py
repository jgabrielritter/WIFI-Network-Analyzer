from __future__ import annotations

from .optimization_models import DeadZoneInvestigation, RoomCoverageSummary


def build_dead_zone_investigations(room_summaries: list[RoomCoverageSummary]) -> list[DeadZoneInvestigation]:
    investigations: list[DeadZoneInvestigation] = []
    for room in room_summaries:
        if room.classification not in {"Likely weak zone", "Likely dead zone", "Target network not observed", "Weak coverage"}:
            continue

        rationale = list(room.evidence)
        if room.target_absent_count > 0:
            rationale.append("Target SSID was absent in one or more scans for this room.")
        if room.strongest_target_rssi_dbm is not None and room.strongest_target_rssi_dbm <= -75:
            rationale.append("Observed target RSSI is materially weaker than recommended indoor levels.")
        if room.high_congestion_observations > 0:
            rationale.append("Channel crowding may also be contributing in this area.")

        investigations.append(
            DeadZoneInvestigation(
                room_name=room.room_name,
                classification=room.classification,
                confidence=room.confidence,
                rationale=rationale,
            )
        )
    return investigations
