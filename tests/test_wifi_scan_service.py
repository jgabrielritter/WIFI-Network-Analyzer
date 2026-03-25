import platform
import subprocess

from wifi_analyzer.wifi_scan_service import WiFiScanService


class _Done:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_scan_service_unsupported_platform(monkeypatch):
    svc = WiFiScanService()
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    result = svc.scan_networks()
    assert result.networks == []
    assert "not supported" in (result.warning or "")


def test_scan_service_linux_missing_nmcli(monkeypatch):
    svc = WiFiScanService()
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr("shutil.which", lambda _: None)
    result = svc.scan_networks()
    assert "nmcli" in (result.warning or "")


def test_scan_service_windows_success(monkeypatch):
    svc = WiFiScanService()
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr("shutil.which", lambda _: "netsh")
    sample = """
SSID 1 : Corp
    Authentication : WPA2-Personal
    Encryption : CCMP
    BSSID 1 : 00:11:22:33:44:55
    Signal : 70%
    Channel : 6
"""
    monkeypatch.setattr(svc, "_run", lambda cmd: _Done(returncode=0, stdout=sample, stderr=""))
    result = svc.scan_networks()
    assert len(result.networks) == 1
    assert result.networks[0].security_mode == "WPA2"


def test_scan_service_command_failure(monkeypatch):
    svc = WiFiScanService()
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr("shutil.which", lambda _: "netsh")
    monkeypatch.setattr(svc, "_run", lambda cmd: _Done(returncode=1, stdout="", stderr="access denied"))
    result = svc.scan_networks()
    assert "failed" in (result.warning or "")


def test_run_wrapper_uses_subprocess():
    svc = WiFiScanService()
    done = svc._run(["python", "-c", "print('ok')"])
    assert isinstance(done, subprocess.CompletedProcess)
    assert done.returncode == 0
