from wifi_analyzer.analytics_config import AnalyticsConfig
from wifi_analyzer.reports import build_export_payload
from wifi_analyzer.scan_history import ScanHistoryStore
from wifi_analyzer.wifi_analytics import WiFiAnalyticsEngine
from wifi_analyzer.wifi_models import WiFiNetworkRecord, WiFiScanResult


def _rec(**kwargs):
    data = dict(
        ssid="OfficeWiFi",
        bssid="00:11:22:33:44:55",
        rssi_dbm=-58,
        signal_percent=72,
        channel=36,
        frequency_mhz=5180,
        band="5 GHz",
        security_mode="WPA2",
        interface_name="wlan0",
    )
    data.update(kwargs)
    return WiFiNetworkRecord(**data)


def test_duplicate_ssid_grouping_and_hidden_handling():
    nets = [
        _rec(ssid="OfficeWiFi", bssid="00:11:22:33:44:55", rssi_dbm=-50, channel=36),
        _rec(ssid="OfficeWiFi", bssid="00:11:22:33:44:56", rssi_dbm=-63, channel=40),
        _rec(ssid="", is_hidden=True, bssid="aa:bb:cc:11:22:33", rssi_dbm=-70, channel=6, band="2.4 GHz"),
    ]
    report = WiFiAnalyticsEngine().build_report(nets)
    assert len(report.groups) == 2
    office = [g for g in report.groups if g.group_key == "OfficeWiFi"][0]
    assert office.access_point_count == 2
    assert office.strongest_bssid == "00:11:22:33:44:55"


def test_strongest_ap_recommendation_and_tie():
    nets = [
        _rec(bssid="00:11:22:33:44:55", rssi_dbm=-58),
        _rec(bssid="00:11:22:33:44:56", rssi_dbm=-60),
    ]
    report = WiFiAnalyticsEngine(AnalyticsConfig(near_tie_dbm=3)).build_report(nets)
    rec = report.recommendations["OfficeWiFi"]
    assert rec.recommended_bssid == "00:11:22:33:44:55"
    assert len(rec.tied_bssids) == 2


def test_channel_congestion_weighting_and_labeling():
    nets = [
        _rec(ssid="A", bssid="00:aa:00:00:00:01", channel=6, band="2.4 GHz", rssi_dbm=-50),
        _rec(ssid="B", bssid="00:aa:00:00:00:02", channel=6, band="2.4 GHz", rssi_dbm=-78),
        _rec(ssid="C", bssid="00:aa:00:00:00:03", channel=149, band="5 GHz", rssi_dbm=-82),
    ]
    report = WiFiAnalyticsEngine().build_report(nets)
    top = report.channel_congestion[0]
    assert top.channel == 6
    assert top.weighted_score > 1.0
    assert top.label in {"Low", "Moderate", "High"}


def test_environment_scoring_reasoning():
    nets = [
        _rec(ssid=f"N{i}", bssid=f"00:bb:00:00:00:{i:02x}", channel=6, band="2.4 GHz", security_mode="Open", rssi_dbm=-60)
        for i in range(1, 8)
    ]
    report = WiFiAnalyticsEngine().build_report(nets)
    assert report.environment.score < 70
    assert report.environment.label in {"Fair", "Poor", "Congested"}
    assert report.environment.reasons


def test_history_insight_and_export_analytics_payload():
    history = ScanHistoryStore()
    older = [_rec(bssid="00:11:22:33:44:01"), _rec(bssid="00:11:22:33:44:02")]
    newer = [_rec(bssid="00:11:22:33:44:02"), _rec(bssid="00:11:22:33:44:03")]
    history.add_result(WiFiScanResult(networks=older, source="nmcli"))
    history.add_result(WiFiScanResult(networks=newer, source="nmcli"))

    snapshots = history.list_snapshots()
    report = WiFiAnalyticsEngine().build_report(newer, latest_snapshot=snapshots[0], previous_snapshot=snapshots[1])
    assert report.history_insight is not None
    assert "appeared" in report.history_insight.summary

    payload = build_export_payload(snapshots=snapshots, redacted=True)
    snapshot_payload = payload["snapshots"][0]
    assert "analytics" in snapshot_payload
    assert "environment" in snapshot_payload["analytics"]
    assert snapshot_payload["analytics"]["disclaimer"]
