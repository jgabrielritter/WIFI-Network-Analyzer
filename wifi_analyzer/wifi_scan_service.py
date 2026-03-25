from __future__ import annotations

import platform
import shutil
import subprocess

from .wifi_models import WiFiScanResult
from .wifi_parser import deduplicate_networks, parse_linux_nmcli_json, parse_macos_airport, parse_windows_netsh


class WiFiScanService:
    """Cross-platform passive Wi-Fi scan service with graceful fallbacks."""

    def scan_networks(self) -> WiFiScanResult:
        system = platform.system().lower()
        if system == "windows":
            return self._scan_windows()
        if system == "linux":
            return self._scan_linux()
        if system == "darwin":
            return self._scan_macos()
        return WiFiScanResult(networks=[], source=system, warning=f"Wi-Fi scanning is not supported on {system}.")

    def _scan_windows(self) -> WiFiScanResult:
        if not shutil.which("netsh"):
            return WiFiScanResult(networks=[], source="netsh", warning="Required tool 'netsh' is unavailable.")

        completed = self._run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        if completed.returncode != 0:
            return WiFiScanResult(networks=[], source="netsh", warning=self._stderr_help(completed.stderr))

        networks = deduplicate_networks(parse_windows_netsh(completed.stdout))
        warning = None if networks else "No nearby Wi-Fi networks were detected."
        return WiFiScanResult(networks=networks, source="netsh", warning=warning)

    def _scan_linux(self) -> WiFiScanResult:
        if not shutil.which("nmcli"):
            return WiFiScanResult(
                networks=[],
                source="nmcli",
                warning="Required tool 'nmcli' not found. Install NetworkManager/nmcli or run on a supported host.",
            )

        cmd = [
            "nmcli",
            "--mode",
            "multiline",
            "--terse",
            "--escape",
            "no",
            "--fields",
            "SSID,BSSID,CHAN,FREQ,SIGNAL,SIGNAL_DBM,SECURITY,DEVICE",
            "--get-values",
            "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SIGNAL_DBM,SECURITY,DEVICE",
            "device",
            "wifi",
            "list",
        ]
        completed = self._run(cmd)
        if completed.returncode != 0:
            return WiFiScanResult(networks=[], source="nmcli", warning=self._stderr_help(completed.stderr))

        # `nmcli` can output unstructured lines across versions; normalize to JSON-like list first.
        rows = []
        for line in completed.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 9:
                continue
            _, ssid, bssid, chan, freq, signal, signal_dbm, security, device = parts[:9]
            rows.append(
                {
                    "SSID": ssid or None,
                    "BSSID": bssid or None,
                    "CHAN": chan or None,
                    "FREQ": freq or None,
                    "SIGNAL": signal or None,
                    "SIGNAL_DBM": signal_dbm or None,
                    "SECURITY": security or None,
                    "DEVICE": device or None,
                }
            )

        import json

        networks = deduplicate_networks(parse_linux_nmcli_json(json.dumps(rows)))
        warning = None if networks else "No nearby Wi-Fi networks were detected or adapter is unavailable."
        return WiFiScanResult(networks=networks, source="nmcli", warning=warning)

    def _scan_macos(self) -> WiFiScanResult:
        airport_path = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        )
        if not shutil.which(airport_path):
            return WiFiScanResult(
                networks=[],
                source="airport",
                warning="The macOS 'airport' scanner utility is unavailable on this host.",
            )

        completed = self._run([airport_path, "-s"])
        if completed.returncode != 0:
            return WiFiScanResult(networks=[], source="airport", warning=self._stderr_help(completed.stderr))

        networks = deduplicate_networks(parse_macos_airport(completed.stdout))
        warning = None if networks else "No nearby Wi-Fi networks were detected."
        return WiFiScanResult(networks=networks, source="airport", warning=warning)

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)

    @staticmethod
    def _stderr_help(stderr: str) -> str:
        text = (stderr or "").strip()
        if not text:
            return "Wi-Fi scan command failed. Check adapter status and permissions."
        return f"Wi-Fi scan failed: {text}"
