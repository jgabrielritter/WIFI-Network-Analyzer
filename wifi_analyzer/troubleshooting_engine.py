from __future__ import annotations

from .comparison_config import ComparisonConfig, DEFAULT_COMPARISON_CONFIG
from .comparison_models import ScanComparisonResult


def build_troubleshooting_summary(
    comparison: ScanComparisonResult,
    target_ssid: str | None = None,
    config: ComparisonConfig = DEFAULT_COMPARISON_CONFIG,
) -> list[str]:
    lines: list[str] = []
    lines.append("Troubleshooting summary (observed-scan comparison):")

    env_delta = int(comparison.deltas.get("environment_score_delta") or 0)
    if abs(env_delta) >= config.thresholds.significant_environment_delta:
        weaker = comparison.left.scan_label if env_delta > 0 else comparison.right.scan_label
        lines.append(
            f"- '{weaker}' has lower observed environment quality. Consider checking placement and obstructions in that area."
        )

    if comparison.channel_delta.get("newly_crowded") not in {None, "None"}:
        lines.append(
            "- The second scan shows additional crowded channels. Consider validating whether the device can use less-crowded bands/channels in that location/time."
        )

    if target_ssid:
        rssi_delta = comparison.ssid_delta.get("rssi_delta_dbm")
        if isinstance(rssi_delta, int) and abs(rssi_delta) >= config.thresholds.meaningful_rssi_delta_dbm:
            weaker = comparison.left.scan_label if rssi_delta > 0 else comparison.right.scan_label
            lines.append(
                f"- {target_ssid} appears weaker in '{weaker}'. Consider investigating AP proximity or whether a farther AP is being favored."
            )
        elif rssi_delta is None:
            lines.append(f"- {target_ssid} was absent in one scan, so direct RSSI deltas are unavailable.")

        left_bssid = comparison.ssid_delta.get("left_strongest_bssid")
        right_bssid = comparison.ssid_delta.get("right_strongest_bssid")
        if left_bssid and right_bssid and left_bssid != right_bssid:
            lines.append(
                "- Strongest observed BSSID changed between comparisons, which can indicate different AP dominance by location/time."
            )

    lines.append(f"- {comparison.disclaimer}")
    return lines
