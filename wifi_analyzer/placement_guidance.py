from __future__ import annotations

from .optimization_config import OptimizationConfig
from .optimization_models import PlacementGuidance, RoomCoverageSummary


def build_placement_guidance(
    room_summaries: list[RoomCoverageSummary], target_ssid: str, config: OptimizationConfig
) -> list[PlacementGuidance]:
    if len(room_summaries) < 2:
        return [
            PlacementGuidance(
                headline="More room samples needed",
                recommendation="Collect scans from at least two labeled rooms before reviewing AP placement balance.",
                evidence=["Current data is insufficient for room-to-room placement guidance."],
            )
        ]

    strongest = room_summaries[0]
    weakest = room_summaries[-1]
    guidance: list[PlacementGuidance] = []

    if strongest.strongest_target_rssi_dbm is not None and weakest.strongest_target_rssi_dbm is not None:
        drop = strongest.strongest_target_rssi_dbm - weakest.strongest_target_rssi_dbm
        if drop >= config.significant_signal_gap_dbm:
            guidance.append(
                PlacementGuidance(
                    headline="Large room-to-room signal drop observed",
                    recommendation=(
                        f"{target_ssid} appears much stronger in {strongest.room_name} than {weakest.room_name}. "
                        "Consider evaluating whether AP placement currently favors one side of the space."
                    ),
                    evidence=[f"Observed strongest target RSSI gap: {drop} dB across sampled rooms."],
                )
            )

    absent_rooms = [r.room_name for r in room_summaries if r.target_present_count == 0]
    if absent_rooms:
        guidance.append(
            PlacementGuidance(
                headline="Target SSID missing in some rooms",
                recommendation=(
                    "Review AP placement relative to rooms where the target SSID was not observed, "
                    "and compare scans from hallways/adjacent areas."
                ),
                evidence=[f"Target SSID absent in: {', '.join(absent_rooms)}."],
            )
        )

    lower_band_rooms = [r.room_name for r in room_summaries if r.dominant_target_band == "2.4 GHz"]
    higher_band_rooms = [r.room_name for r in room_summaries if r.dominant_target_band in {"5 GHz", "6 GHz"}]
    if lower_band_rooms and higher_band_rooms:
        guidance.append(
            PlacementGuidance(
                headline="Higher-band reach appears uneven",
                recommendation=(
                    "Higher-band visibility appears stronger in some rooms than others. "
                    "Consider checking whether AP location or obstructions are limiting 5/6 GHz reach."
                ),
                evidence=[
                    f"Mostly 2.4 GHz rooms: {', '.join(lower_band_rooms)}.",
                    f"Rooms with 5/6 GHz dominance: {', '.join(higher_band_rooms)}.",
                ],
            )
        )

    multi_bssid_rooms = [r.room_name for r in room_summaries if r.multiple_target_bssids_visible]
    if multi_bssid_rooms:
        guidance.append(
            PlacementGuidance(
                headline="Coverage balance across BSSIDs should be reviewed",
                recommendation=(
                    "Multiple target BSSIDs dominate in different rooms. "
                    "Consider checking AP power/channel balance and room-level roaming behavior."
                ),
                evidence=[f"Rooms with multiple observed target BSSIDs: {', '.join(multi_bssid_rooms)}."],
            )
        )

    if not guidance:
        guidance.append(
            PlacementGuidance(
                headline="No major placement imbalance detected",
                recommendation=(
                    "Current scans do not show a strong placement issue. Continue collecting room-tagged scans "
                    "at different times for stronger evidence."
                ),
                evidence=["No severe RSSI drop or repeated missing-target pattern was observed."],
            )
        )

    return guidance
