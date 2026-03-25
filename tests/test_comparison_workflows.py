from pathlib import Path

from wifi_analyzer.reports import (
    build_comparison_payload,
    export_comparison_csv,
    export_comparison_json,
    export_comparison_text,
)
from wifi_analyzer.scan_comparison import compare_snapshots, compare_ssid_across_snapshots
from wifi_analyzer.scan_history import ScanContext, ScanHistoryStore
from wifi_analyzer.trend_analysis import build_environment_score_trend, build_ssid_signal_trend
from wifi_analyzer.troubleshooting_engine import build_troubleshooting_summary
from wifi_analyzer.wifi_models import WiFiNetworkRecord, WiFiScanResult


def _network(**kwargs):
    data = dict(
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
    data.update(kwargs)
    return WiFiNetworkRecord(**data)


def test_location_context_labeling_and_edit():
    history = ScanHistoryStore()
    snap = history.add_result(
        WiFiScanResult(networks=[_network()], source="nmcli"),
        context=ScanContext(scan_label="Morning", room_name="Office", location_name="Upstairs"),
    )
    assert snap.context.to_display_label() == "Morning | Office | Upstairs"

    updated = history.update_context(snap.snapshot_id, ScanContext(scan_label="Evening", room_name="Bedroom"))
    assert updated is not None
    assert updated.context.scan_label == "Evening"


def test_scan_to_scan_comparison_and_ssid_delta():
    history = ScanHistoryStore()
    first = history.add_result(
        WiFiScanResult(networks=[_network(rssi_dbm=-72, bssid="00:11:22:33:44:01")], source="nmcli"),
        context=ScanContext(scan_label="Bedroom"),
    )
    second = history.add_result(
        WiFiScanResult(
            networks=[
                _network(rssi_dbm=-60, bssid="00:11:22:33:44:02"),
                _network(ssid="Neighbor", bssid="00:11:22:33:44:99", channel=1, band="2.4 GHz", security_mode="Open"),
            ],
            source="nmcli",
        ),
        context=ScanContext(scan_label="Office"),
    )

    comparison = compare_snapshots(first, second, target_ssid="HomeWiFi")
    assert comparison.deltas["network_count_delta"] == 1
    assert comparison.ssid_delta["rssi_delta_dbm"] == 12
    assert comparison.ssid_delta["left_strongest_bssid"] != comparison.ssid_delta["right_strongest_bssid"]


def test_absent_ssid_handling_and_troubleshooting_lines():
    history = ScanHistoryStore()
    first = history.add_result(WiFiScanResult(networks=[_network(ssid="Other")], source="nmcli"))
    second = history.add_result(WiFiScanResult(networks=[_network(ssid="HomeWiFi")], source="nmcli"))

    comparison = compare_snapshots(first, second, target_ssid="HomeWiFi")
    lines = build_troubleshooting_summary(comparison, target_ssid="HomeWiFi")
    assert comparison.ssid_delta["rssi_delta_dbm"] is None
    assert any("absent" in line.lower() for line in lines)


def test_ssid_observation_trend_and_environment_trend():
    history = ScanHistoryStore()
    first = history.add_result(WiFiScanResult(networks=[_network(rssi_dbm=-70)], source="nmcli"))
    second = history.add_result(WiFiScanResult(networks=[_network(rssi_dbm=-62)], source="nmcli"))

    ssid_obs = compare_ssid_across_snapshots([first, second], target_ssid="HomeWiFi")
    assert len(ssid_obs) == 2
    assert ssid_obs[0].present is True

    env_trend = build_environment_score_trend([first, second])
    ssid_trend = build_ssid_signal_trend([first, second], target_ssid="HomeWiFi")
    assert len(env_trend) == 2
    assert len(ssid_trend) == 2


def test_comparison_exports(tmp_path: Path):
    history = ScanHistoryStore()
    first = history.add_result(WiFiScanResult(networks=[_network(rssi_dbm=-68)], source="nmcli"), context=ScanContext(scan_label="A"))
    second = history.add_result(WiFiScanResult(networks=[_network(rssi_dbm=-58)], source="nmcli"), context=ScanContext(scan_label="B"))

    payload = build_comparison_payload(first, second, target_ssid="HomeWiFi")
    assert "deltas" in payload
    assert payload["target_ssid"] == "HomeWiFi"

    out_json = tmp_path / "comparison.json"
    out_csv = tmp_path / "comparison.csv"
    out_txt = tmp_path / "comparison.txt"
    export_comparison_json(out_json, first, second, target_ssid="HomeWiFi")
    export_comparison_csv(out_csv, first, second, target_ssid="HomeWiFi")
    export_comparison_text(out_txt, first, second, target_ssid="HomeWiFi")

    assert out_json.exists()
    assert out_csv.exists()
    assert out_txt.exists()
