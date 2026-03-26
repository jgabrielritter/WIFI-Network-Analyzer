from __future__ import annotations

import json
import uuid
from pathlib import Path

from .floorplan_models import APMarker, FloorPlanLayout, RoomNode


class FloorPlanStore:
    def __init__(self) -> None:
        self._plans: dict[str, FloorPlanLayout] = {}

    def create_plan(self, name: str, width: int = 960, height: int = 540) -> FloorPlanLayout:
        plan = FloorPlanLayout(plan_id=str(uuid.uuid4()), name=name.strip() or "Floor Plan", width=width, height=height)
        self._plans[plan.plan_id] = plan
        return plan

    def upsert_plan(self, plan: FloorPlanLayout) -> None:
        self._plans[plan.plan_id] = plan

    def get(self, plan_id: str) -> FloorPlanLayout | None:
        return self._plans.get(plan_id)

    def add_room(
        self,
        plan_id: str,
        room_name: str,
        x: float,
        y: float,
        width: float = 140,
        height: float = 90,
        floor_zone: str | None = None,
    ) -> RoomNode:
        plan = self._require(plan_id)
        room = RoomNode(
            room_id=str(uuid.uuid4()),
            room_name=room_name.strip() or "Room",
            x=x,
            y=y,
            width=width,
            height=height,
            floor_zone=floor_zone,
        )
        plan.rooms.append(room)
        return room

    def add_ap_marker(
        self,
        plan_id: str,
        label: str,
        x: float,
        y: float,
        marker_type: str = "unknown",
        ssid: str | None = None,
    ) -> APMarker:
        plan = self._require(plan_id)
        marker = APMarker(
            marker_id=str(uuid.uuid4()),
            label=label.strip() or "AP",
            x=x,
            y=y,
            marker_type=marker_type,
            ssid=ssid,
        )
        plan.ap_markers.append(marker)
        return marker

    def move_room(self, plan_id: str, room_id: str, x: float, y: float) -> RoomNode:
        plan = self._require(plan_id)
        room = plan.get_room(room_id)
        if room is None:
            raise KeyError(f"Unknown room_id: {room_id}")
        room.x = x
        room.y = y
        return room

    def move_ap_marker(self, plan_id: str, marker_id: str, x: float, y: float) -> APMarker:
        plan = self._require(plan_id)
        marker = plan.get_marker(marker_id)
        if marker is None:
            raise KeyError(f"Unknown marker_id: {marker_id}")
        marker.x = x
        marker.y = y
        return marker

    def save_to_file(self, plan_id: str, path: Path) -> None:
        plan = self._require(plan_id)
        payload = {
            "format": "wifi-analyzer-floor-plan-v1",
            "plan": plan.to_dict(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load_from_file(self, path: Path) -> FloorPlanLayout:
        payload = json.loads(path.read_text(encoding="utf-8"))
        plan = FloorPlanLayout.from_dict(payload["plan"])
        self.upsert_plan(plan)
        return plan

    def _require(self, plan_id: str) -> FloorPlanLayout:
        plan = self.get(plan_id)
        if plan is None:
            raise KeyError(f"Unknown plan_id: {plan_id}")
        return plan
