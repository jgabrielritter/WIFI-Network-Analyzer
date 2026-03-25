from wifi_analyzer.privacy import mask_ip, mask_mac
from wifi_analyzer.vendor_lookup import get_vendor


def test_mask_ip_and_mac():
    assert mask_ip("192.168.1.87") == "192.168.1.x"
    assert mask_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:xx:xx:xx"


def test_vendor_fallback_map():
    assert get_vendor("00:50:F2:11:22:33") == "Microsoft"
    assert get_vendor("FF:EE:DD:11:22:33") in {"Unknown", ""}
