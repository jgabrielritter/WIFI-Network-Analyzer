from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .dashboard_logic import format_signal_bars, normalize_band_badge, security_chip_presentation
from .privacy import mask_mac
from .scan_history import ScanSnapshot
from .wifi_models import WiFiNetworkRecord


def _network_to_dict(network: WiFiNetworkRecord, redacted: bool) -> dict[str, str | int | None]:
    security = security_chip_presentation(network.security_mode)
    bssid = mask_mac(network.bssid) if redacted and network.bssid else network.bssid
    return {
        "ssid": network.display_ssid,
        "bssid": bssid,
        "rssi_dbm": network.rssi_dbm,
        "signal_percent": network.signal_percent,
        "signal_bars": format_signal_bars(network.rssi_dbm, network.signal_percent),
        "signal_quality": network.signal_quality_label,
        "channel": network.channel,
        "frequency_mhz": network.frequency_mhz,
        "band": normalize_band_badge(network.band),
        "security": security.chip,
        "security_risk_level": security.risk_level,
        "scan_timestamp": network.scan_timestamp,
        "interface": network.interface_name,
    }


def build_export_payload(snapshots: list[ScanSnapshot], redacted: bool) -> dict[str, object]:
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "redacted": redacted,
        "snapshot_count": len(snapshots),
        "snapshots": [
            {
                "snapshot_id": snapshot.snapshot_id,
                "scan_timestamp": snapshot.created_at,
                "source": snapshot.source,
                "interface": snapshot.interface_name,
                "warning": snapshot.warning,
                "network_count": len(snapshot.networks),
                "networks": [_network_to_dict(network, redacted=redacted) for network in snapshot.networks],
            }
            for snapshot in snapshots
        ],
    }


def export_json(path: Path, snapshots: list[ScanSnapshot], redacted: bool) -> None:
    payload = build_export_payload(snapshots=snapshots, redacted=redacted)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_csv(path: Path, snapshots: list[ScanSnapshot], redacted: bool) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "snapshot_id",
                "scan_timestamp",
                "source",
                "interface",
                "ssid",
                "bssid",
                "rssi_dbm",
                "signal_percent",
                "signal_bars",
                "signal_quality",
                "channel",
                "frequency_mhz",
                "band",
                "security",
                "security_risk_level",
                "network_scan_timestamp",
            ],
        )
        writer.writeheader()
        for snapshot in snapshots:
            for network in snapshot.networks:
                network_dict = _network_to_dict(network, redacted=redacted)
                writer.writerow(
                    {
                        "snapshot_id": snapshot.snapshot_id,
                        "scan_timestamp": snapshot.created_at,
                        "source": snapshot.source,
                        "interface": snapshot.interface_name,
                        "ssid": network_dict["ssid"],
                        "bssid": network_dict["bssid"],
                        "rssi_dbm": network_dict["rssi_dbm"],
                        "signal_percent": network_dict["signal_percent"],
                        "signal_bars": network_dict["signal_bars"],
                        "signal_quality": network_dict["signal_quality"],
                        "channel": network_dict["channel"],
                        "frequency_mhz": network_dict["frequency_mhz"],
                        "band": network_dict["band"],
                        "security": network_dict["security"],
                        "security_risk_level": network_dict["security_risk_level"],
                        "network_scan_timestamp": network_dict["scan_timestamp"],
                    }
                )


def export_text_report(path: Path, snapshots: list[ScanSnapshot], redacted: bool) -> None:
    payload = build_export_payload(snapshots=snapshots, redacted=redacted)
    lines = [
        "WiFi Network Analyzer Report",
        f"Export timestamp: {payload['exported_at']}",
        f"Redacted mode: {'Yes' if redacted else 'No'}",
        f"Snapshots: {payload['snapshot_count']}",
        "",
    ]

    for snapshot in payload["snapshots"]:
        lines.append(f"Snapshot {snapshot['snapshot_id']} ({snapshot['scan_timestamp']})")
        lines.append(f"  Source: {snapshot['source']} | Interface: {snapshot['interface'] or 'Unknown'}")
        lines.append(f"  Networks: {snapshot['network_count']}")
        if snapshot["warning"]:
            lines.append(f"  Warning: {snapshot['warning']}")
        for network in snapshot["networks"]:
            lines.append(
                f"    - {network['ssid']} | {network['bssid'] or 'N/A'} | {network['signal_bars']} {network['signal_quality']} | "
                f"CH {network['channel'] or 'N/A'} | {network['band']} | {network['security']}"
            )
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
