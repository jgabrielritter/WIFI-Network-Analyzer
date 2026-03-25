from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .wifi_models import WiFiNetworkRecord


def frequency_to_channel(frequency_mhz: int | None) -> int | None:
    if frequency_mhz is None:
        return None
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if frequency_mhz == 2484:
        return 14
    if 5000 <= frequency_mhz <= 5895:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:
        return (frequency_mhz - 5950) // 5
    return None


def infer_band(channel: int | None = None, frequency_mhz: int | None = None) -> str:
    if frequency_mhz is not None:
        if 2400 <= frequency_mhz < 2500:
            return "2.4 GHz"
        if 5000 <= frequency_mhz < 5925:
            return "5 GHz"
        if 5925 <= frequency_mhz < 7125:
            return "6 GHz"

    if channel is not None:
        if 1 <= channel <= 14:
            return "2.4 GHz"
        if 32 <= channel <= 177:
            return "5 GHz"
        if 1 <= channel <= 233:
            return "6 GHz"

    return "Unknown"


def normalize_security_mode(raw: str | None) -> str:
    if not raw:
        return "Unknown"
    text = raw.upper()
    if "OPEN" in text or text.strip() in {"NONE", "--"}:
        return "Open"
    if "WEP" in text:
        return "WEP"
    has_wpa3 = "WPA3" in text or "SAE" in text
    has_wpa2 = "WPA2" in text or "RSN" in text
    has_wpa = re.search(r"\bWPA\b", text) is not None

    if has_wpa3 and has_wpa2:
        return "WPA2/WPA3"
    if has_wpa3:
        return "WPA3"
    if has_wpa2 and has_wpa:
        return "WPA/WPA2"
    if has_wpa2:
        return "WPA2"
    if has_wpa:
        return "WPA"
    return "Unknown"


def _normalize_bssid(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().replace("-", ":").lower()
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", candidate):
        return candidate
    return None


def _hidden_from_ssid(ssid: str | None) -> bool:
    return ssid is None or ssid.strip() == ""


def normalize_record(
    *,
    ssid: str | None,
    bssid: str | None,
    channel: int | None,
    frequency_mhz: int | None,
    rssi_dbm: int | None,
    signal_percent: int | None,
    security_raw: str | None,
    interface_name: str | None,
    source: dict,
) -> WiFiNetworkRecord:
    if channel is None and frequency_mhz is not None:
        channel = frequency_to_channel(frequency_mhz)
    band = infer_band(channel=channel, frequency_mhz=frequency_mhz)
    ssid_value = ssid.strip() if isinstance(ssid, str) else None
    if ssid_value == "":
        ssid_value = None
    normalized_bssid = _normalize_bssid(bssid)

    return WiFiNetworkRecord(
        ssid=ssid_value,
        bssid=normalized_bssid,
        rssi_dbm=rssi_dbm,
        signal_percent=signal_percent,
        channel=channel,
        frequency_mhz=frequency_mhz,
        band=band,
        security_mode=normalize_security_mode(security_raw),
        encryption_details=security_raw.strip() if isinstance(security_raw, str) and security_raw.strip() else None,
        interface_name=interface_name,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        is_hidden=_hidden_from_ssid(ssid_value),
        raw_source=source,
    )


def parse_windows_netsh(raw_text: str) -> list[WiFiNetworkRecord]:
    networks: list[WiFiNetworkRecord] = []
    current: dict[str, str] = {}
    ssid_name: str | None = None

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^SSID\s+\d+\s*:", stripped):
            if current:
                networks.append(_record_from_windows(ssid_name, current))
                current = {}
            ssid_name = stripped.split(":", 1)[1].strip() or None
            continue
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            current[key.strip().lower()] = value.strip()

    if current:
        networks.append(_record_from_windows(ssid_name, current))

    return [item for item in networks if item.bssid is not None or not item.is_hidden]


def _record_from_windows(ssid_name: str | None, data: dict[str, str]) -> WiFiNetworkRecord:
    bssid = data.get("bssid 1") or data.get("bssid")
    signal_percent = _to_int(data.get("signal", "").replace("%", ""))
    channel = _to_int(data.get("channel"))
    security_raw = " ".join(part for part in [data.get("authentication"), data.get("encryption")] if part)
    return normalize_record(
        ssid=ssid_name,
        bssid=bssid,
        channel=channel,
        frequency_mhz=None,
        rssi_dbm=None,
        signal_percent=signal_percent,
        security_raw=security_raw,
        interface_name=data.get("interface name"),
        source={"platform": "windows", "raw": data},
    )


def parse_linux_nmcli_json(raw_text: str) -> list[WiFiNetworkRecord]:
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return []

    networks: list[WiFiNetworkRecord] = []
    for item in parsed if isinstance(parsed, list) else []:
        if not isinstance(item, dict):
            continue
        freq = _to_int(item.get("FREQ"))
        networks.append(
            normalize_record(
                ssid=item.get("SSID"),
                bssid=item.get("BSSID"),
                channel=_to_int(item.get("CHAN")),
                frequency_mhz=freq,
                rssi_dbm=_to_int(item.get("SIGNAL_DBM")),
                signal_percent=_to_int(item.get("SIGNAL")),
                security_raw=item.get("SECURITY"),
                interface_name=item.get("DEVICE"),
                source={"platform": "linux", "raw": item},
            )
        )
    return networks


def parse_macos_airport(raw_text: str) -> list[WiFiNetworkRecord]:
    lines = [line.rstrip() for line in raw_text.splitlines() if line.strip()]
    if len(lines) <= 1:
        return []

    networks: list[WiFiNetworkRecord] = []
    for row in lines[1:]:
        match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", row)
        if not match:
            continue
        bssid = match.group(1)
        left = row[: match.start()].rstrip()
        right = row[match.end() :].strip()

        ssid = left if left else None
        right_parts = right.split()
        rssi = _to_int(right_parts[0]) if len(right_parts) >= 1 else None
        channel = _to_int(re.split(r"[, ]", right_parts[1])[0]) if len(right_parts) >= 2 else None
        security_raw = " ".join(right_parts[3:]) if len(right_parts) >= 4 else None

        networks.append(
            normalize_record(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                frequency_mhz=None,
                rssi_dbm=rssi,
                signal_percent=None,
                security_raw=security_raw,
                interface_name="airport",
                source={"platform": "macos", "raw": row},
            )
        )
    return networks


def deduplicate_networks(networks: list[WiFiNetworkRecord]) -> list[WiFiNetworkRecord]:
    best_by_bssid: dict[str, WiFiNetworkRecord] = {}
    no_bssid: list[WiFiNetworkRecord] = []

    for network in networks:
        if not network.bssid:
            no_bssid.append(network)
            continue
        existing = best_by_bssid.get(network.bssid)
        if existing is None:
            best_by_bssid[network.bssid] = network
            continue
        if _sort_signal_key(network) > _sort_signal_key(existing):
            best_by_bssid[network.bssid] = network

    return sorted([*best_by_bssid.values(), *no_bssid], key=_sort_signal_key, reverse=True)


def _sort_signal_key(network: WiFiNetworkRecord) -> int:
    if network.rssi_dbm is not None:
        return network.rssi_dbm
    if network.signal_percent is not None:
        return network.signal_percent - 100
    return -999


def _to_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"-?\d+", text)
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None
