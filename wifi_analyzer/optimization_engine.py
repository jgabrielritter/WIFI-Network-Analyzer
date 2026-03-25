from __future__ import annotations

from dataclasses import asdict

from .comparison_models import ScanProfile
from .dead_zone_detection import build_dead_zone_investigations
from .improvement_planner import build_improvement_plan
from .optimization_config import DEFAULT_OPTIMIZATION_CONFIG, OptimizationConfig
from .optimization_models import OptimizationResult
from .placement_guidance import build_placement_guidance
from .scan_comparison import build_scan_profile
from .scan_history import ScanSnapshot
from .coverage_analysis import summarize_room_coverage


class OptimizationEngine:
    def __init__(self, config: OptimizationConfig = DEFAULT_OPTIMIZATION_CONFIG) -> None:
        self.config = config

    def build_guidance(self, snapshots: list[ScanSnapshot], target_ssid: str) -> OptimizationResult:
        target = target_ssid.strip()
        if not target:
            raise ValueError("A target SSID is required for optimization guidance.")

        profiles: dict[str, ScanProfile] = {snap.snapshot_id: build_scan_profile(snap) for snap in snapshots}
        room_summaries = summarize_room_coverage(snapshots=snapshots, target_ssid=target, profiles=profiles, config=self.config)
        if not room_summaries:
            return OptimizationResult(
                target_ssid=target,
                strongest_room=None,
                weakest_room=None,
                room_summaries=[],
                likely_weak_zones=[],
                likely_dead_zones=[],
                placement_guidance=[],
                investigations=[],
                improvement_plan=[],
                summary_lines=["No room-tagged scans are available yet. Add labeled scans and retry optimization guidance."],
                confidence_label="Limited evidence",
                disclaimer=self.config.heuristics_disclaimer,
            )

        strongest_room = room_summaries[0].room_name
        weakest_room = room_summaries[-1].room_name
        likely_weak = [r.room_name for r in room_summaries if r.classification in {"Likely weak zone", "Weak coverage"}]
        likely_dead = [r.room_name for r in room_summaries if r.classification in {"Likely dead zone", "Target network not observed"}]

        placement = build_placement_guidance(room_summaries=room_summaries, target_ssid=target, config=self.config)
        investigations = build_dead_zone_investigations(room_summaries)
        plan = build_improvement_plan(room_summaries=room_summaries, config=self.config)

        confidence = "Limited evidence"
        if any(r.confidence == "Strong repeated evidence" for r in room_summaries):
            confidence = "Strong repeated evidence"
        elif any(r.confidence == "Moderate evidence" for r in room_summaries):
            confidence = "Moderate evidence"

        summary_lines = [
            f"{target} appears strongest in {strongest_room} and weakest in {weakest_room} based on observed scans.",
        ]
        if likely_dead:
            summary_lines.append(f"Likely dead-zone candidates: {', '.join(likely_dead)}.")
        elif likely_weak:
            summary_lines.append(f"Likely weak-coverage areas: {', '.join(likely_weak)}.")
        if placement:
            summary_lines.append(placement[0].recommendation)
        if plan:
            summary_lines.append(f"Prioritize investigation in {plan[0].room_name} first.")

        return OptimizationResult(
            target_ssid=target,
            strongest_room=strongest_room,
            weakest_room=weakest_room,
            room_summaries=room_summaries,
            likely_weak_zones=likely_weak,
            likely_dead_zones=likely_dead,
            placement_guidance=placement,
            investigations=investigations,
            improvement_plan=plan,
            summary_lines=summary_lines,
            confidence_label=confidence,
            disclaimer=self.config.heuristics_disclaimer,
        )


def optimization_result_to_dict(result: OptimizationResult) -> dict[str, object]:
    return asdict(result)
