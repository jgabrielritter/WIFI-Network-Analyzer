from __future__ import annotations

from dataclasses import dataclass

from .wifi_models import WiFiNetworkRecord


def rssi_to_quality_label(rssi_dbm: int | None, signal_percent: int | None = None) -> str:
    if rssi_dbm is not None:
        if rssi_dbm >= -55:
            return "Excellent"
        if rssi_dbm >= -67:
            return "Good"
        if rssi_dbm >= -75:
            return "Fair"
        return "Weak"

    if signal_percent is not None:
        if signal_percent >= 80:
            return "Excellent"
        if signal_percent >= 60:
            return "Good"
        if signal_percent >= 40:
            return "Fair"
        return "Weak"

    return "Unknown"


def signal_to_bar_level(rssi_dbm: int | None, signal_percent: int | None = None) -> int | None:
    """Returns 0-4 bars, or None when no signal data is available."""
    if rssi_dbm is not None:
        if rssi_dbm >= -55:
            return 4
        if rssi_dbm >= -67:
            return 3
        if rssi_dbm >= -75:
            return 2
        if rssi_dbm >= -85:
            return 1
        return 0

    if signal_percent is not None:
        if signal_percent >= 80:
            return 4
        if signal_percent >= 60:
            return 3
        if signal_percent >= 40:
            return 2
        if signal_percent >= 20:
            return 1
        return 0

    return None


def format_signal_bars(rssi_dbm: int | None, signal_percent: int | None = None) -> str:
    level = signal_to_bar_level(rssi_dbm=rssi_dbm, signal_percent=signal_percent)
    if level is None:
        return "□□□□"
    return "■" * level + "□" * (4 - level)


def format_signal_cell(network: WiFiNetworkRecord) -> str:
    bars = format_signal_bars(network.rssi_dbm, network.signal_percent)
    if network.rssi_dbm is not None:
        return f"{bars} {network.rssi_dbm} dBm"
    if network.signal_percent is not None:
        return f"{bars} {network.signal_percent}%"
    return f"{bars} N/A"


def normalize_band_badge(band: str | None) -> str:
    raw = (band or "").lower()
    if "2.4" in raw:
        return "2.4 GHz"
    if raw.startswith("5") or " 5" in raw:
        return "5 GHz"
    if raw.startswith("6") or " 6" in raw:
        return "6 GHz"
    return "Unknown"


def normalize_security_chip(security_mode: str | None) -> str:
    raw = (security_mode or "").strip().upper()
    if not raw or raw == "UNKNOWN":
        return "Unknown"
    if "OPEN" in raw or raw in {"NONE", "--"}:
        return "Open"
    if "WEP" in raw:
        return "WEP"
    if "WPA2/WPA3" in raw or ("WPA2" in raw and "WPA3" in raw):
        return "WPA2/WPA3"
    if "WPA3" in raw:
        return "WPA3"
    if "WPA2" in raw:
        return "WPA2"
    if "WPA" in raw:
        return "WPA"
    if "MIX" in raw:
        return "Mixed"
    return "Unknown"


@dataclass(frozen=True)
class SecurityPresentation:
    chip: str
    risk_level: str


def security_chip_presentation(security_mode: str | None) -> SecurityPresentation:
    chip = normalize_security_chip(security_mode)
    if chip in {"Open", "WEP"}:
        return SecurityPresentation(chip=chip, risk_level="high")
    if chip in {"Unknown", "WPA"}:
        return SecurityPresentation(chip=chip, risk_level="medium")
    return SecurityPresentation(chip=chip, risk_level="low")


def compute_scan_summary(networks: list[WiFiNetworkRecord]) -> dict[str, str]:
    open_count = 0
    by_band = {"2.4 GHz": 0, "5 GHz": 0, "6 GHz": 0, "Unknown": 0}
    strongest: WiFiNetworkRecord | None = None

    for network in networks:
        chip = normalize_security_chip(network.security_mode)
        if chip == "Open":
            open_count += 1
        band = normalize_band_badge(network.band)
        by_band[band] = by_band.get(band, 0) + 1

        if strongest is None:
            strongest = network
            continue

        if (network.rssi_dbm is not None) and (strongest.rssi_dbm is not None):
            if network.rssi_dbm > strongest.rssi_dbm:
                strongest = network
        elif network.rssi_dbm is not None and strongest.rssi_dbm is None:
            strongest = network

    strongest_display = strongest.signal_display if strongest else "N/A"

    return {
        "total": str(len(networks)),
        "open": str(open_count),
        "strongest": strongest_display,
        "band_24": str(by_band.get("2.4 GHz", 0)),
        "band_5": str(by_band.get("5 GHz", 0)),
        "band_6": str(by_band.get("6 GHz", 0)),
    }
