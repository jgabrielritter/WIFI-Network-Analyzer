from pathlib import Path

from wifi_analyzer.optimization_engine import OptimizationEngine
from wifi_analyzer.reports import (
    build_optimization_payload,
    export_optimization_csv,
    export_optimization_json,
    export_optimization_text,
)
from wifi_analyzer.scan_history import ScanContext, ScanHistoryStore
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
        context=ScanContext(room_name=room),
    )


def test_room_coverage_ranking_and_dead_zone_heuristics():
    history = ScanHistoryStore()
    _snapshot(history, "Office", [_record(rssi_dbm=-48, bssid="00:11:22:33:44:01", band="5 GHz")])
    _snapshot(history, "Office", [_record(rssi_dbm=-50, bssid="00:11:22:33:44:01", band="5 GHz")])
    _snapshot(history, "Bedroom", [_record(rssi_dbm=-74, bssid="00:11:22:33:44:02", band="2.4 GHz", channel=6)])
    _snapshot(history, "Basement", [_record(ssid="Neighbor", bssid="00:99:88:77:66:11", rssi_dbm=-65, channel=1, band="2.4 GHz")])

    result = OptimizationEngine().build_guidance(history.list_snapshots(), target_ssid="HomeWiFi")

    assert result.strongest_room == "Office"
    assert "Basement" in result.likely_dead_zones
    assert any(item.room_name == "Basement" and item.priority_level == "High" for item in result.improvement_plan)


def test_target_ssid_comparison_and_band_fallback():
    history = ScanHistoryStore()
    _snapshot(history, "Living Room", [_record(rssi_dbm=-55, band="5 GHz", bssid="00:11:22:33:44:09")])
    _snapshot(history, "Kitchen", [_record(rssi_dbm=-70, band="2.4 GHz", channel=11, bssid="00:11:22:33:44:0a")])

    result = OptimizationEngine().build_guidance(history.list_snapshots(), target_ssid="HomeWiFi")
    by_room = {room.room_name: room for room in result.room_summaries}

    assert by_room["Kitchen"].dominant_target_band == "2.4 GHz"
    assert by_room["Living Room"].dominant_target_band == "5 GHz"
    assert result.placement_guidance


def test_confidence_and_repeated_scan_confirmation():
    history = ScanHistoryStore()
    for _ in range(4):
        _snapshot(history, "Hallway", [_record(rssi_dbm=-80, band="2.4 GHz", channel=1)])

    result = OptimizationEngine().build_guidance(history.list_snapshots(), target_ssid="HomeWiFi")
    hallway = next(room for room in result.room_summaries if room.room_name == "Hallway")
    assert hallway.confidence == "Strong repeated evidence"


def test_optimization_exports_and_sparse_data(tmp_path: Path):
    history = ScanHistoryStore()
    _snapshot(history, "Garage", [_record(ssid="Other", bssid="10:20:30:40:50:60", rssi_dbm=-60, band="2.4 GHz")])

    payload = build_optimization_payload(history.list_snapshots(), target_ssid="HomeWiFi")
    assert payload["optimization"]["room_summaries"]

    out_json = tmp_path / "optimization.json"
    out_csv = tmp_path / "optimization.csv"
    out_txt = tmp_path / "optimization.txt"
    export_optimization_json(out_json, history.list_snapshots(), target_ssid="HomeWiFi")
    export_optimization_csv(out_csv, history.list_snapshots(), target_ssid="HomeWiFi")
    export_optimization_text(out_txt, history.list_snapshots(), target_ssid="HomeWiFi")

    assert out_json.exists()
    assert out_csv.exists()
    assert out_txt.exists()
    assert "priority_level" in out_csv.read_text(encoding="utf-8")
