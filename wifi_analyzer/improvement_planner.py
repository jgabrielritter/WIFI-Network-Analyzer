from __future__ import annotations

from .optimization_config import OptimizationConfig
from .optimization_models import ImprovementPlanItem, RoomCoverageSummary


PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _priority_for_room(room: RoomCoverageSummary, config: OptimizationConfig) -> tuple[str, int, str, str]:
    score = 0
    if room.classification == "Likely dead zone":
        score += config.dead_zone_priority_boost
    elif room.classification in {"Likely weak zone", "Weak coverage", "Target network not observed"}:
        score += config.weak_zone_priority_boost

    if room.target_present_count == 0:
        score += config.missing_target_priority_boost

    if room.high_congestion_observations > 0:
        score += config.high_congestion_priority_boost

    if room.dominant_target_band == "2.4 GHz":
        score += config.lower_band_only_priority_boost

    if room.strongest_target_rssi_dbm is not None:
        score += max(0, min(35, abs(room.strongest_target_rssi_dbm) - 50))

    observed_issue = room.classification
    next_step = (
        "Compare scans near adjacent rooms/hallways and verify whether AP coverage reaches this area reliably."
        if room.classification in {"Likely dead zone", "Target network not observed"}
        else "Run repeated scans at doorway and in-room center, then review AP placement relative to this room."
    )
    if room.high_congestion_observations > 0:
        next_step += " Also review channel crowding during peak times."

    if score >= 70:
        return "High", score, observed_issue, next_step
    if score >= 50:
        return "Medium", score, observed_issue, next_step
    return "Low", score, observed_issue, next_step


def build_improvement_plan(
    room_summaries: list[RoomCoverageSummary],
    config: OptimizationConfig,
) -> list[ImprovementPlanItem]:
    items: list[ImprovementPlanItem] = []
    for room in room_summaries:
        level, score, issue, step = _priority_for_room(room, config)
        items.append(
            ImprovementPlanItem(
                priority_rank=0,
                priority_level=level,
                room_name=room.room_name,
                observed_issue=issue,
                evidence=room.evidence,
                suggested_next_step=step,
                confidence=room.confidence,
                score=score,
            )
        )

    items = sorted(items, key=lambda i: (PRIORITY_ORDER[i.priority_level], -i.score, i.room_name.lower()))
    return [
        ImprovementPlanItem(
            priority_rank=index,
            priority_level=item.priority_level,
            room_name=item.room_name,
            observed_issue=item.observed_issue,
            evidence=item.evidence,
            suggested_next_step=item.suggested_next_step,
            confidence=item.confidence,
            score=item.score,
        )
        for index, item in enumerate(items, start=1)
    ]
