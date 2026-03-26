from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RoomNode:
    room_id: str
    room_name: str
    x: float
    y: float
    width: float = 140.0
    height: float = 90.0
    floor_zone: str | None = None
    notes: str | None = None
    linked_labels: list[str] = field(default_factory=list)

    def matches_label(self, value: str | None) -> bool:
        if not value:
            return False
        lowered = value.strip().lower()
        if not lowered:
            return False
        if self.room_name.strip().lower() == lowered:
            return True
        return any(label.strip().lower() == lowered for label in self.linked_labels)

    def to_dict(self) -> dict[str, Any]:
        return {
            "room_id": self.room_id,
            "room_name": self.room_name,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "floor_zone": self.floor_zone,
            "notes": self.notes,
            "linked_labels": list(self.linked_labels),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RoomNode":
        return cls(
            room_id=str(payload["room_id"]),
            room_name=str(payload["room_name"]),
            x=float(payload.get("x", 0.0)),
            y=float(payload.get("y", 0.0)),
            width=float(payload.get("width", 140.0)),
            height=float(payload.get("height", 90.0)),
            floor_zone=payload.get("floor_zone"),
            notes=payload.get("notes"),
            linked_labels=[str(item) for item in payload.get("linked_labels", [])],
        )


@dataclass
class APMarker:
    marker_id: str
    label: str
    x: float
    y: float
    marker_type: str = "unknown"
    ssid: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "marker_id": self.marker_id,
            "label": self.label,
            "x": self.x,
            "y": self.y,
            "marker_type": self.marker_type,
            "ssid": self.ssid,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "APMarker":
        return cls(
            marker_id=str(payload["marker_id"]),
            label=str(payload.get("label", "AP")),
            x=float(payload.get("x", 0.0)),
            y=float(payload.get("y", 0.0)),
            marker_type=str(payload.get("marker_type", "unknown")),
            ssid=payload.get("ssid"),
            notes=payload.get("notes"),
        )


@dataclass
class FloorPlanLayout:
    plan_id: str
    name: str
    width: int = 960
    height: int = 540
    floor_zone: str | None = None
    notes: str | None = None
    background_image_path: str | None = None
    rooms: list[RoomNode] = field(default_factory=list)
    ap_markers: list[APMarker] = field(default_factory=list)

    def get_room(self, room_id: str) -> RoomNode | None:
        return next((item for item in self.rooms if item.room_id == room_id), None)

    def get_marker(self, marker_id: str) -> APMarker | None:
        return next((item for item in self.ap_markers if item.marker_id == marker_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "name": self.name,
            "width": self.width,
            "height": self.height,
            "floor_zone": self.floor_zone,
            "notes": self.notes,
            "background_image_path": self.background_image_path,
            "rooms": [room.to_dict() for room in self.rooms],
            "ap_markers": [marker.to_dict() for marker in self.ap_markers],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FloorPlanLayout":
        return cls(
            plan_id=str(payload["plan_id"]),
            name=str(payload.get("name", "Floor Plan")),
            width=int(payload.get("width", 960)),
            height=int(payload.get("height", 540)),
            floor_zone=payload.get("floor_zone"),
            notes=payload.get("notes"),
            background_image_path=payload.get("background_image_path"),
            rooms=[RoomNode.from_dict(item) for item in payload.get("rooms", [])],
            ap_markers=[APMarker.from_dict(item) for item in payload.get("ap_markers", [])],
        )
