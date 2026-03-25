from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RoomCoverageSummary:
    room_name: str
    scans_count: int
    strongest_observed_ssid: str | None
    strongest_observed_bssid: str | None
    strongest_target_rssi_dbm: int | None
    dominant_target_band: str | None
    multiple_target_bssids_visible: bool
    target_absent_count: int
    target_present_count: int
    high_congestion_observations: int
    avg_environment_score: float | None
    environment_relative_label: str
    classification: str
    confidence: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DeadZoneInvestigation:
    room_name: str
    classification: str
    confidence: str
    rationale: list[str]


@dataclass(frozen=True)
class PlacementGuidance:
    headline: str
    recommendation: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ImprovementPlanItem:
    priority_rank: int
    priority_level: str
    room_name: str
    observed_issue: str
    evidence: list[str]
    suggested_next_step: str
    confidence: str
    score: int


@dataclass(frozen=True)
class OptimizationResult:
    target_ssid: str
    strongest_room: str | None
    weakest_room: str | None
    room_summaries: list[RoomCoverageSummary]
    likely_weak_zones: list[str]
    likely_dead_zones: list[str]
    placement_guidance: list[PlacementGuidance]
    investigations: list[DeadZoneInvestigation]
    improvement_plan: list[ImprovementPlanItem]
    summary_lines: list[str]
    confidence_label: str
    disclaimer: str
