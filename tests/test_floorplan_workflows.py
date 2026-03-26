from pathlib import Path

from wifi_analyzer.reports import (
    build_floorplan_export_payload,
    export_floorplan_html,
    export_floorplan_json,
    export_floorplan_text,
)
from wifi_analyzer.room_map import FloorPlanStore
from wifi_analyzer.scan_history import ScanContext, ScanHistoryStore
from wifi_analyzer.visual_coverage_plan import build_floor_plan_coverage, describe_ap_placement
from wifi_analyzer.wifi_models import WiFiNetworkRecord, WiFiScanResult


def _record(**kwargs):
    base = dict(
        ssid="HomeWiFi",
        bssid="00:11:22:33:44:55",
        rssi_dbm=-60,
        signal_percent=70,
        channel=36,
        frequency_mhz=5180,
        band="5 GHz",
        security_mode="WPA2",
        interface_name="wlan0",
    )
    base.update(kwargs)
    return WiFiNetworkRecord(**base)


def _snapshot(history: ScanHistoryStore, room: str, networks: list[WiFiNetworkRecord]):
    return history.add_result(
        WiFiScanResult(networks=networks, source="nmcli"),
        context=ScanContext(room_name=room, location_name=room),
    )


def test_floorplan_model_and_persistence(tmp_path: Path):
    store = FloorPlanStore()
    plan = store.create_plan("Home")
    room = store.add_room(plan.plan_id, "Office", 100, 120)
    room.linked_labels.extend(["office", "desk"])
    marker = store.add_ap_marker(plan.plan_id, "Main AP", 200, 80, marker_type="main_ap", ssid="HomeWiFi")

    out = tmp_path / "layout.json"
    store.save_to_file(plan.plan_id, out)
    loaded = store.load_from_file(out)

    assert loaded.rooms[0].room_name == "Office"
    assert loaded.rooms[0].matches_label("desk")
    assert loaded.ap_markers[0].label == marker.label


def test_room_association_classification_priority_and_evidence():
    history = ScanHistoryStore()
    _snapshot(history, "Office", [_record(rssi_dbm=-52, band="5 GHz")])
    _snapshot(history, "Basement", [_record(ssid="OtherNet", rssi_dbm=-70, band="2.4 GHz")])
    _snapshot(history, "Bedroom", [_record(rssi_dbm=-78, band="2.4 GHz")])
    _snapshot(history, "Bedroom", [_record(rssi_dbm=-80, band="2.4 GHz")])

    store = FloorPlanStore()
    plan = store.create_plan("Home")
    office = store.add_room(plan.plan_id, "Office", 100, 100)
    basement = store.add_room(plan.plan_id, "Basement", 260, 200)
    bedroom = store.add_room(plan.plan_id, "Bedroom", 420, 120)
    store.add_room(plan.plan_id, "Garage", 580, 120)
    office.linked_labels.append("office")
    basement.linked_labels.append("basement")
    bedroom.linked_labels.append("bedroom")

    report = build_floor_plan_coverage(plan=plan, snapshots=history.list_snapshots(), target_ssid="HomeWiFi")
    by_room = {item.room_name: item for item in report.room_states}

    assert by_room["Office"].status in {"Strong coverage", "Good coverage"}
    assert by_room["Basement"].status == "Likely dead zone"
    assert by_room["Bedroom"].status in {"Weak coverage", "Likely weak zone"}
    assert by_room["Garage"].status == "Insufficient data"
    assert by_room["Bedroom"].scan_count == 2
    assert "Single-scan evidence" not in by_room["Bedroom"].confidence_label


def test_floorplan_exports_and_ap_review(tmp_path: Path):
    history = ScanHistoryStore()
    _snapshot(history, "Living Room", [_record(rssi_dbm=-58, band="5 GHz")])
    _snapshot(history, "Back Office", [_record(rssi_dbm=-83, band="2.4 GHz")])

    store = FloorPlanStore()
    plan = store.create_plan("Level 1")
    store.add_room(plan.plan_id, "Living Room", 100, 120)
    store.add_room(plan.plan_id, "Back Office", 700, 120)
    store.add_ap_marker(plan.plan_id, "Router", 120, 90, marker_type="main_ap", ssid="HomeWiFi")

    payload = build_floorplan_export_payload(plan=plan, snapshots=history.list_snapshots(), target_ssid="HomeWiFi")
    assert payload["coverage"]["target_ssid"] == "HomeWiFi"
    assert payload["ap_placement_review"]

    out_json = tmp_path / "plan.json"
    out_txt = tmp_path / "plan.txt"
    out_html = tmp_path / "plan.html"
    export_floorplan_json(out_json, plan, history.list_snapshots(), target_ssid="HomeWiFi")
    export_floorplan_text(out_txt, plan, history.list_snapshots(), target_ssid="HomeWiFi")
    export_floorplan_html(out_html, plan, history.list_snapshots(), target_ssid="HomeWiFi")

    assert out_json.exists()
    assert out_txt.exists()
    assert out_html.exists()
    assert "visual planning guidance" in out_txt.read_text(encoding="utf-8").lower()

    report = build_floor_plan_coverage(plan=plan, snapshots=history.list_snapshots(), target_ssid="HomeWiFi")
    review = describe_ap_placement(plan, report)
    assert review
