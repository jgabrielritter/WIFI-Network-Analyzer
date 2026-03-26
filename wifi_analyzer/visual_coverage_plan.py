from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .floorplan_models import APMarker, FloorPlanLayout, RoomNode
from .scan_history import ScanSnapshot


STATUS_ORDER = {
    "Likely dead zone": 0,
    "Likely weak zone": 1,
    "Weak coverage": 2,
    "Usable coverage": 3,
    "Good coverage": 4,
    "Strong coverage": 5,
    "Insufficient data": 6,
}


@dataclass(frozen=True)
class RoomCoverageState:
    room_id: str
    room_name: str
    status: str
    strongest_target_rssi_dbm: int | None
    strongest_observed_bssid: str | None
    dominant_band: str | None
    security_mode: str | None
    target_present_count: int
    target_absent_count: int
    scan_count: int
    confidence_label: str
    latest_scan_at: str | None
    priority_rank: int
    notes: list[str]


@dataclass(frozen=True)
class FloorPlanCoverageReport:
    plan_id: str
    plan_name: str
    target_ssid: str
    generated_at: str
    room_states: list[RoomCoverageState]
    weak_rooms: list[str]
    dead_rooms: list[str]
    summary_lines: list[str]
    disclaimer: str


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _room_matches_snapshot(room: RoomNode, snapshot: ScanSnapshot) -> bool:
    ctx = snapshot.context
    return any(
        room.matches_label(candidate)
        for candidate in [ctx.room_name, ctx.location_name, ctx.scan_label]
    )


def _confidence(scan_count: int, latest_scan_at: str | None, target_present_count: int) -> str:
    if scan_count == 0:
        return "No evidence"
    age_note = ""
    ts = _parse_ts(latest_scan_at)
    if ts:
        age_days = (datetime.now(timezone.utc) - ts.astimezone(timezone.utc)).days
        if age_days > 30:
            age_note = " (stale)"
    if scan_count >= 3 and target_present_count > 0:
        return f"Strong repeated evidence{age_note}"
    if scan_count >= 2:
        return f"Moderate evidence{age_note}"
    return f"Single-scan evidence{age_note}"


def _classify(strongest: int | None, present: int, absent: int, scan_count: int) -> str:
    if scan_count == 0:
        return "Insufficient data"
    if present == 0:
        return "Likely dead zone"
    if strongest is None:
        return "Insufficient data"
    if strongest >= -55:
        return "Strong coverage"
    if strongest >= -65:
        return "Good coverage"
    if strongest >= -72:
        return "Usable coverage"
    if strongest >= -80:
        return "Weak coverage"
    if absent >= present and scan_count >= 2:
        return "Likely dead zone"
    return "Likely weak zone"


def build_floor_plan_coverage(
    plan: FloorPlanLayout,
    snapshots: list[ScanSnapshot],
    target_ssid: str,
) -> FloorPlanCoverageReport:
    target = target_ssid.strip()
    if not target:
        raise ValueError("Target SSID is required for floor-plan coverage mode.")

    states: list[RoomCoverageState] = []
    for room in plan.rooms:
        room_scans = [snap for snap in snapshots if _room_matches_snapshot(room, snap)]
        strongest: int | None = None
        strongest_bssid: str | None = None
        dominant_band_counts: dict[str, int] = {}
        security_counts: dict[str, int] = {}
        present = 0
        absent = 0
        latest: str | None = None
        for scan in room_scans:
            if latest is None or scan.created_at > latest:
                latest = scan.created_at
            target_networks = [net for net in scan.networks if net.ssid.strip().lower() == target.lower()]
            if not target_networks:
                absent += 1
                continue
            present += 1
            best = max(target_networks, key=lambda net: net.rssi_dbm if net.rssi_dbm is not None else -999)
            if best.rssi_dbm is not None and (strongest is None or best.rssi_dbm > strongest):
                strongest = best.rssi_dbm
                strongest_bssid = best.bssid
            band = best.band or "Unknown"
            dominant_band_counts[band] = dominant_band_counts.get(band, 0) + 1
            security = best.security_mode or "Unknown"
            security_counts[security] = security_counts.get(security, 0) + 1

        dominant_band = max(dominant_band_counts, key=dominant_band_counts.get) if dominant_band_counts else None
        security_mode = max(security_counts, key=security_counts.get) if security_counts else None
        status = _classify(strongest=strongest, present=present, absent=absent, scan_count=len(room_scans))
        notes: list[str] = []
        if len(room_scans) == 0:
            notes.append("No mapped scans yet. Capture scans with room/location labels.")
        elif present == 0:
            notes.append("Target SSID was absent in mapped scans for this room.")
        if len(room_scans) == 1:
            notes.append("Single scan only; add repeat scans for stronger confidence.")
        if dominant_band == "2.4 GHz" and present > 0:
            notes.append("Coverage relies mostly on 2.4 GHz observations.")
        confidence = _confidence(scan_count=len(room_scans), latest_scan_at=latest, target_present_count=present)
        states.append(
            RoomCoverageState(
                room_id=room.room_id,
                room_name=room.room_name,
                status=status,
                strongest_target_rssi_dbm=strongest,
                strongest_observed_bssid=strongest_bssid,
                dominant_band=dominant_band,
                security_mode=security_mode,
                target_present_count=present,
                target_absent_count=absent,
                scan_count=len(room_scans),
                confidence_label=confidence,
                latest_scan_at=latest,
                priority_rank=0,
                notes=notes,
            )
        )

    ranked = sorted(states, key=lambda item: (STATUS_ORDER.get(item.status, 999), item.strongest_target_rssi_dbm or -999))
    rehydrated: list[RoomCoverageState] = []
    for idx, item in enumerate(ranked, start=1):
        rehydrated.append(
            RoomCoverageState(
                room_id=item.room_id,
                room_name=item.room_name,
                status=item.status,
                strongest_target_rssi_dbm=item.strongest_target_rssi_dbm,
                strongest_observed_bssid=item.strongest_observed_bssid,
                dominant_band=item.dominant_band,
                security_mode=item.security_mode,
                target_present_count=item.target_present_count,
                target_absent_count=item.target_absent_count,
                scan_count=item.scan_count,
                confidence_label=item.confidence_label,
                latest_scan_at=item.latest_scan_at,
                priority_rank=idx,
                notes=item.notes,
            )
        )

    weak = [item.room_name for item in rehydrated if item.status in {"Likely weak zone", "Weak coverage"}]
    dead = [item.room_name for item in rehydrated if item.status == "Likely dead zone"]

    summary_lines = [
        f"Target SSID '{target}' coverage map is based on mapped scan labels and heuristic room-level classification.",
    ]
    if rehydrated:
        strongest = max(rehydrated, key=lambda item: item.strongest_target_rssi_dbm or -999)
        weakest = min(rehydrated, key=lambda item: item.strongest_target_rssi_dbm or -999)
        summary_lines.append(f"Strongest observed room: {strongest.room_name}; weakest observed room: {weakest.room_name}.")
    if dead:
        summary_lines.append(f"Likely dead-zone candidates: {', '.join(dead)}.")
    elif weak:
        summary_lines.append(f"Likely weak-zone candidates: {', '.join(weak)}.")
    under_sampled = [item.room_name for item in rehydrated if item.scan_count <= 1]
    if under_sampled:
        summary_lines.append(f"More scans are recommended for: {', '.join(under_sampled)}.")

    return FloorPlanCoverageReport(
        plan_id=plan.plan_id,
        plan_name=plan.name,
        target_ssid=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        room_states=rehydrated,
        weak_rooms=weak,
        dead_rooms=dead,
        summary_lines=summary_lines,
        disclaimer=(
            "Room-based visual planning guidance only. Findings are derived from observed scans and heuristics, "
            "not precise RF propagation or professional site-survey modeling."
        ),
    )


def describe_ap_placement(plan: FloorPlanLayout, report: FloorPlanCoverageReport) -> list[str]:
    if not plan.ap_markers or not report.room_states:
        return ["AP placement review needs user-placed AP/router markers and mapped room scans."]

    weak_ids = {item.room_id for item in report.room_states if item.status in {"Likely dead zone", "Likely weak zone", "Weak coverage"}}
    if not weak_ids:
        return ["No obvious weak-room cluster is visible in current mapped evidence."]

    weak_rooms = [room for room in plan.rooms if room.room_id in weak_ids]
    weak_avg_x = sum(room.x for room in weak_rooms) / len(weak_rooms)
    marker_avg_x = sum(marker.x for marker in plan.ap_markers) / len(plan.ap_markers)
    direction = "east" if weak_avg_x > marker_avg_x else "west"

    markers = ", ".join(marker.label for marker in plan.ap_markers)
    return [
        f"Coverage weakness appears stronger toward the {direction} side of the map relative to markers ({markers}).",
        "Review AP placement and room-level obstacles near weak rooms using additional repeat scans before making placement changes.",
    ]


def coverage_report_to_dict(plan: FloorPlanLayout, report: FloorPlanCoverageReport) -> dict[str, object]:
    return {
        "format": "wifi-analyzer-visual-coverage-v1",
        "plan": plan.to_dict(),
        "coverage": {
            "plan_id": report.plan_id,
            "plan_name": report.plan_name,
            "target_ssid": report.target_ssid,
            "generated_at": report.generated_at,
            "room_states": [item.__dict__ for item in report.room_states],
            "weak_rooms": report.weak_rooms,
            "dead_rooms": report.dead_rooms,
            "summary_lines": report.summary_lines,
            "disclaimer": report.disclaimer,
        },
    }
