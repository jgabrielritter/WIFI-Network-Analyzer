from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .dashboard_logic import format_signal_bars, normalize_band_badge, security_chip_presentation
from .privacy import mask_mac
from .scan_history import ScanSnapshot
from .scan_comparison import compare_snapshots
from .troubleshooting_engine import build_troubleshooting_summary
from .wifi_analytics import WiFiAnalyticsEngine, WiFiAnalyticsReport, group_key_for_network
from .wifi_models import WiFiNetworkRecord
from .optimization_engine import OptimizationEngine, optimization_result_to_dict


def _network_to_dict(
    network: WiFiNetworkRecord,
    redacted: bool,
    analytics: WiFiAnalyticsReport | None = None,
    hidden_group_name: str = "<Hidden SSID Group>",
) -> dict[str, str | int | bool | None]:
    security = security_chip_presentation(network.security_mode)
    bssid = mask_mac(network.bssid) if redacted and network.bssid else network.bssid

    group_key = group_key_for_network(network, hidden_group_name=hidden_group_name)
    rank = analytics.network_rank_by_bssid.get(network.bssid or "") if analytics and network.bssid else None
    strongest_bssid = analytics.strongest_bssid_by_group.get(group_key) if analytics else None

    congestion_label = "Unknown"
    congestion_count = None
    if analytics and network.channel is not None:
        for channel in analytics.channel_congestion:
            if channel.channel == network.channel and channel.band == normalize_band_badge(network.band):
                congestion_label = channel.label
                congestion_count = channel.network_count
                break

    return {
        "ssid": network.display_ssid,
        "ssid_group": group_key,
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
        "group_rank": rank,
        "is_group_strongest": bool(network.bssid and strongest_bssid and network.bssid == strongest_bssid),
        "channel_congestion_label": congestion_label,
        "channel_network_count": congestion_count,
        "environment_score": analytics.environment.score if analytics else None,
        "environment_label": analytics.environment.label if analytics else None,
    }


def _build_snapshot_payload(snapshot: ScanSnapshot, redacted: bool, engine: WiFiAnalyticsEngine) -> dict[str, object]:
    analytics = engine.build_report(snapshot.networks)
    hidden_group_name = engine.config.hidden_ssid_group_name
    return {
        "snapshot_id": snapshot.snapshot_id,
        "scan_timestamp": snapshot.created_at,
        "source": snapshot.source,
        "interface": snapshot.interface_name,
        "warning": snapshot.warning,
        "network_count": len(snapshot.networks),
        "analytics": {
            "disclaimer": "Observed-scan insights using heuristic analytics. Not a direct airtime/performance measurement.",
            "environment": {
                "score": analytics.environment.score,
                "label": analytics.environment.label,
                "reasons": analytics.environment.reasons,
            },
            "channel_congestion": [channel.__dict__ for channel in analytics.channel_congestion],
            "ssid_groups": [
                {
                    "ssid_group": group.ssid_display,
                    "access_point_count": group.access_point_count,
                    "strongest_bssid": mask_mac(group.strongest_bssid) if redacted and group.strongest_bssid else group.strongest_bssid,
                    "strongest_signal_dbm": group.strongest_signal_dbm,
                    "channels": group.channels,
                    "bands": group.bands,
                    "security_modes": group.security_modes,
                    "is_security_mixed": group.is_security_mixed,
                }
                for group in analytics.groups
            ],
            "recommendations": {
                key: {
                    "recommended_bssid": mask_mac(value.recommended_bssid) if redacted and value.recommended_bssid else value.recommended_bssid,
                    "recommendation_text": value.recommendation_text,
                    "tied_bssids": [mask_mac(item) if redacted else item for item in value.tied_bssids],
                }
                for key, value in analytics.recommendations.items()
            },
            "insights": analytics.insights,
        },
        "context": snapshot.context.to_dict(),
        "networks": [
            _network_to_dict(network, redacted=redacted, analytics=analytics, hidden_group_name=hidden_group_name)
            for network in snapshot.networks
        ],
    }


def build_export_payload(snapshots: list[ScanSnapshot], redacted: bool) -> dict[str, object]:
    engine = WiFiAnalyticsEngine()
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "redacted": redacted,
        "snapshot_count": len(snapshots),
        "snapshots": [_build_snapshot_payload(snapshot, redacted=redacted, engine=engine) for snapshot in snapshots],
    }


def export_json(path: Path, snapshots: list[ScanSnapshot], redacted: bool) -> None:
    payload = build_export_payload(snapshots=snapshots, redacted=redacted)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_csv(path: Path, snapshots: list[ScanSnapshot], redacted: bool) -> None:
    engine = WiFiAnalyticsEngine()
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "snapshot_id",
                "scan_timestamp",
                "source",
                "interface",
                "ssid",
                "ssid_group",
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
                "group_rank",
                "is_group_strongest",
                "channel_congestion_label",
                "channel_network_count",
                "environment_score",
                "environment_label",
            ],
        )
        writer.writeheader()
        for snapshot in snapshots:
            analytics = engine.build_report(snapshot.networks)
            for network in snapshot.networks:
                network_dict = _network_to_dict(
                    network,
                    redacted=redacted,
                    analytics=analytics,
                    hidden_group_name=engine.config.hidden_ssid_group_name,
                )
                writer.writerow(
                    {
                        "snapshot_id": snapshot.snapshot_id,
                        "scan_timestamp": snapshot.created_at,
                        "source": snapshot.source,
                        "interface": snapshot.interface_name,
                        "ssid": network_dict["ssid"],
                        "ssid_group": network_dict["ssid_group"],
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
                        "group_rank": network_dict["group_rank"],
                        "is_group_strongest": network_dict["is_group_strongest"],
                        "channel_congestion_label": network_dict["channel_congestion_label"],
                        "channel_network_count": network_dict["channel_network_count"],
                        "environment_score": network_dict["environment_score"],
                        "environment_label": network_dict["environment_label"],
                    }
                )


def export_text_report(path: Path, snapshots: list[ScanSnapshot], redacted: bool) -> None:
    payload = build_export_payload(snapshots=snapshots, redacted=redacted)
    lines = [
        "WiFi Network Analyzer Report",
        f"Export timestamp: {payload['exported_at']}",
        f"Redacted mode: {'Yes' if redacted else 'No'}",
        "Note: analytics are observed-scan heuristics, not guaranteed performance measurements.",
        f"Snapshots: {payload['snapshot_count']}",
        "",
    ]

    for snapshot in payload["snapshots"]:
        lines.append(f"Snapshot {snapshot['snapshot_id']} ({snapshot['scan_timestamp']})")
        lines.append(f"  Source: {snapshot['source']} | Interface: {snapshot['interface'] or 'Unknown'}")
        lines.append(f"  Networks: {snapshot['network_count']}")
        env = snapshot["analytics"]["environment"]
        lines.append(f"  Environment: {env['label']} ({env['score']}/100)")
        for reason in env["reasons"]:
            lines.append(f"    - {reason}")
        if snapshot["warning"]:
            lines.append(f"  Warning: {snapshot['warning']}")
        for network in snapshot["networks"]:
            lines.append(
                f"    - {network['ssid']} | {network['bssid'] or 'N/A'} | {network['signal_bars']} {network['signal_quality']} | "
                f"CH {network['channel'] or 'N/A'} ({network['channel_congestion_label']}) | {network['band']} | {network['security']}"
            )
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def build_comparison_payload(
    left: ScanSnapshot,
    right: ScanSnapshot,
    target_ssid: str | None = None,
) -> dict[str, object]:
    comparison = compare_snapshots(left, right, target_ssid=target_ssid)
    troubleshooting = build_troubleshooting_summary(comparison, target_ssid=target_ssid)
    return {
        "left_snapshot_id": left.snapshot_id,
        "right_snapshot_id": right.snapshot_id,
        "left_label": left.context.to_display_label(),
        "right_label": right.context.to_display_label(),
        "target_ssid": target_ssid,
        "deltas": comparison.deltas,
        "ssid_delta": comparison.ssid_delta,
        "channel_delta": comparison.channel_delta,
        "findings": comparison.findings,
        "troubleshooting": troubleshooting,
        "disclaimer": comparison.disclaimer,
    }


def export_comparison_json(path: Path, left: ScanSnapshot, right: ScanSnapshot, target_ssid: str | None = None) -> None:
    payload = build_comparison_payload(left=left, right=right, target_ssid=target_ssid)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_comparison_csv(path: Path, left: ScanSnapshot, right: ScanSnapshot, target_ssid: str | None = None) -> None:
    payload = build_comparison_payload(left=left, right=right, target_ssid=target_ssid)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["left_label", "right_label", "metric", "value", "note"],
        )
        writer.writeheader()
        for key, value in payload["deltas"].items():
            writer.writerow({"left_label": payload["left_label"], "right_label": payload["right_label"], "metric": key, "value": value, "note": ""})
        for key, value in payload["ssid_delta"].items():
            writer.writerow({"left_label": payload["left_label"], "right_label": payload["right_label"], "metric": f"ssid_{key}", "value": value, "note": payload.get("target_ssid") or ""})
        for line in payload["troubleshooting"]:
            writer.writerow({"left_label": payload["left_label"], "right_label": payload["right_label"], "metric": "troubleshooting", "value": "", "note": line})


def export_comparison_text(path: Path, left: ScanSnapshot, right: ScanSnapshot, target_ssid: str | None = None) -> None:
    payload = build_comparison_payload(left=left, right=right, target_ssid=target_ssid)
    lines = [
        "WiFi Network Analyzer Comparison Report",
        f"Left: {payload['left_label']} ({left.created_at})",
        f"Right: {payload['right_label']} ({right.created_at})",
        f"Target SSID: {target_ssid or 'N/A'}",
        "",
        "Deltas:",
    ]
    for key, value in payload["deltas"].items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("Findings:")
    for item in payload["findings"] or ["No notable differences detected from current thresholds."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("Troubleshooting suggestions:")
    for item in payload["troubleshooting"]:
        lines.append(item)
    lines.append("")
    lines.append(f"Disclaimer: {payload['disclaimer']}")
    path.write_text("\n".join(lines), encoding="utf-8")


def build_optimization_payload(snapshots: list[ScanSnapshot], target_ssid: str) -> dict[str, object]:
    engine = OptimizationEngine()
    result = engine.build_guidance(snapshots=snapshots, target_ssid=target_ssid)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_ssid": target_ssid,
        "snapshot_count": len(snapshots),
        "room_count": len(result.room_summaries),
        "optimization": optimization_result_to_dict(result),
        "disclaimer": result.disclaimer,
    }


def export_optimization_json(path: Path, snapshots: list[ScanSnapshot], target_ssid: str) -> None:
    payload = build_optimization_payload(snapshots=snapshots, target_ssid=target_ssid)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_optimization_csv(path: Path, snapshots: list[ScanSnapshot], target_ssid: str) -> None:
    payload = build_optimization_payload(snapshots=snapshots, target_ssid=target_ssid)
    room_summaries = payload["optimization"]["room_summaries"]  # type: ignore[index]
    plan_items = payload["optimization"]["improvement_plan"]  # type: ignore[index]
    plan_by_room = {item["room_name"]: item for item in plan_items}

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "target_ssid",
                "room_name",
                "classification",
                "confidence",
                "strongest_target_rssi_dbm",
                "dominant_target_band",
                "target_absent_count",
                "target_present_count",
                "high_congestion_observations",
                "environment_relative_label",
                "priority_level",
                "priority_rank",
                "observed_issue",
                "suggested_next_step",
            ],
        )
        writer.writeheader()
        for summary in room_summaries:
            plan = plan_by_room.get(summary["room_name"], {})
            writer.writerow(
                {
                    "target_ssid": target_ssid,
                    "room_name": summary["room_name"],
                    "classification": summary["classification"],
                    "confidence": summary["confidence"],
                    "strongest_target_rssi_dbm": summary["strongest_target_rssi_dbm"],
                    "dominant_target_band": summary["dominant_target_band"],
                    "target_absent_count": summary["target_absent_count"],
                    "target_present_count": summary["target_present_count"],
                    "high_congestion_observations": summary["high_congestion_observations"],
                    "environment_relative_label": summary["environment_relative_label"],
                    "priority_level": plan.get("priority_level", "N/A"),
                    "priority_rank": plan.get("priority_rank", ""),
                    "observed_issue": plan.get("observed_issue", ""),
                    "suggested_next_step": plan.get("suggested_next_step", ""),
                }
            )


def export_optimization_text(path: Path, snapshots: list[ScanSnapshot], target_ssid: str) -> None:
    payload = build_optimization_payload(snapshots=snapshots, target_ssid=target_ssid)
    optimization = payload["optimization"]  # type: ignore[index]
    lines = [
        "WiFi Network Analyzer Optimization Plan",
        f"Generated: {payload['generated_at']}",
        f"Target SSID: {target_ssid}",
        f"Snapshots analyzed: {payload['snapshot_count']}",
        f"Rooms analyzed: {payload['room_count']}",
        "",
        "Summary:",
    ]
    for line in optimization["summary_lines"]:
        lines.append(f"- {line}")
    lines.append("")
    lines.append("Room Coverage:")
    for room in optimization["room_summaries"]:
        lines.append(
            f"- {room['room_name']}: {room['classification']} ({room['confidence']}), "
            f"best observed RSSI {room['strongest_target_rssi_dbm']} dBm, dominant band {room['dominant_target_band'] or 'N/A'}"
        )
    lines.append("")
    lines.append("Prioritized Improvement Plan:")
    for item in optimization["improvement_plan"]:
        lines.append(f"{item['priority_rank']}. {item['room_name']} [{item['priority_level']}] - {item['observed_issue']}")
        lines.append(f"   Next step: {item['suggested_next_step']}")
    lines.append("")
    lines.append(f"Disclaimer: {payload['disclaimer']}")
    path.write_text("\n".join(lines), encoding="utf-8")
