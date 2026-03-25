import time

from wifi_analyzer.scapy_compat import scapy

from wifi_analyzer.models import InterfaceInfo
from wifi_analyzer.packet_capture_service import PacketCaptureService


class _DummyIP:
    def __init__(self, src: str, dst: str, proto: int = 6):
        self.src = src
        self.dst = dst
        self.proto = proto


class _DummyPacket:
    def haslayer(self, layer):
        return layer == scapy.IP

    def __getitem__(self, item):
        if item == scapy.IP:
            return _DummyIP("10.0.0.10", "10.0.0.5")
        raise KeyError(item)


def test_capture_start_stop_state_transitions(monkeypatch):
    service = PacketCaptureService()
    iface = InterfaceInfo(name="eth0", display_name="eth0", ipv4="10.0.0.2", netmask="255.255.255.0")
    packets = []

    def fake_sniff(**kwargs):
        kwargs["prn"](_DummyPacket())
        time.sleep(0.01)

    monkeypatch.setattr(scapy, "sniff", fake_sniff)

    started = service.start(iface, on_packet=packets.append, on_error=lambda _: None, redact=True)
    assert started is True
    assert service.running is True

    time.sleep(0.05)
    service.stop()
    time.sleep(0.05)

    assert service.running is False
    assert packets, "expected packet callback to be invoked"
