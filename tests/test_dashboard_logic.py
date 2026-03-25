from pathlib import Path

from wifi_analyzer.dashboard_logic import (
    compute_scan_summary,
    format_signal_bars,
    normalize_band_badge,
    normalize_security_chip,
    rssi_to_quality_label,
    security_chip_presentation,
    signal_to_bar_level,
)
from wifi_analyzer.reports import build_export_payload, export_csv, export_json
from wifi_analyzer.scan_history import ScanHistoryStore
from wifi_analyzer.wifi_models import WiFiNetworkRecord, WiFiScanResult


def _record(**kwargs):
    base = dict(
        ssid="Lab",
        bssid="aa:bb:cc:dd:ee:ff",
        rssi_dbm=-60,
        signal_percent=75,
        channel=36,
        frequency_mhz=5180,
        band="5 GHz",
        security_mode="WPA2",
        interface_name="wlan0",
    )
    base.update(kwargs)
    return WiFiNetworkRecord(**base)


def test_signal_bar_and_quality_helpers():
    assert signal_to_bar_level(-52) == 4
    assert signal_to_bar_level(-70) == 2
    assert signal_to_bar_level(None, 65) == 3
    assert signal_to_bar_level(None, None) is None
    assert format_signal_bars(-60) == "■■■□"
    assert rssi_to_quality_label(-58) == "Good"


def test_band_and_security_normalization_helpers():
    assert normalize_band_badge("2.4ghz") == "2.4 GHz"
    assert normalize_band_badge("6 GHz") == "6 GHz"
    assert normalize_band_badge(None) == "Unknown"

    assert normalize_security_chip("wpa2") == "WPA2"
    assert normalize_security_chip("open") == "Open"
    assert security_chip_presentation("wep").risk_level == "high"


def test_scan_summary_and_history_retention():
    n1 = _record(ssid="A", bssid="00:11:22:33:44:55", band="2.4 GHz", security_mode="Open", rssi_dbm=-45)
    n2 = _record(ssid="B", bssid="66:11:22:33:44:55", band="5 GHz", security_mode="WPA2", rssi_dbm=-72)
    summary = compute_scan_summary([n1, n2])
    assert summary["total"] == "2"
    assert summary["open"] == "1"
    assert summary["band_24"] == "1"

    history = ScanHistoryStore(max_entries=2)
    history.add_result(WiFiScanResult(networks=[n1], source="nmcli"))
    history.add_result(WiFiScanResult(networks=[n2], source="nmcli"))
    history.add_result(WiFiScanResult(networks=[n1, n2], source="nmcli"))
    assert len(history.list_snapshots()) == 2


def test_export_payload_and_files(tmp_path: Path):
    history = ScanHistoryStore()
    history.add_result(WiFiScanResult(networks=[_record()], source="nmcli"))
    snapshots = history.list_snapshots()

    payload = build_export_payload(snapshots=snapshots, redacted=True)
    assert payload["snapshot_count"] == 1
    first_network = payload["snapshots"][0]["networks"][0]
    assert "xx" in (first_network["bssid"] or "")

    json_out = tmp_path / "out.json"
    csv_out = tmp_path / "out.csv"
    export_json(json_out, snapshots, redacted=False)
    export_csv(csv_out, snapshots, redacted=True)
    assert json_out.exists()
    assert csv_out.exists()
    assert "snapshot_id" in csv_out.read_text(encoding="utf-8")
