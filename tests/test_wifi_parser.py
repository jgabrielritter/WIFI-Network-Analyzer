from wifi_analyzer.wifi_parser import (
    deduplicate_networks,
    frequency_to_channel,
    infer_band,
    normalize_record,
    normalize_security_mode,
    parse_linux_nmcli_json,
    parse_macos_airport,
    parse_windows_netsh,
)


def test_frequency_to_channel_derivation():
    assert frequency_to_channel(2412) == 1
    assert frequency_to_channel(5180) == 36
    assert frequency_to_channel(5955) == 1
    assert frequency_to_channel(9999) is None


def test_band_derivation_from_frequency_and_channel():
    assert infer_band(frequency_mhz=2462) == "2.4 GHz"
    assert infer_band(channel=149) == "5 GHz"
    assert infer_band(frequency_mhz=6055) == "6 GHz"
    assert infer_band(channel=None, frequency_mhz=None) == "Unknown"


def test_security_mode_normalization():
    assert normalize_security_mode("Open") == "Open"
    assert normalize_security_mode("WPA2-PSK") == "WPA2"
    assert normalize_security_mode("WPA2 WPA3 SAE") == "WPA2/WPA3"
    assert normalize_security_mode("") == "Unknown"


def test_hidden_ssid_handling_and_model_normalization():
    record = normalize_record(
        ssid="",
        bssid="AA-BB-CC-DD-EE-FF",
        channel=6,
        frequency_mhz=None,
        rssi_dbm=-60,
        signal_percent=None,
        security_raw="WPA2",
        interface_name="wlan0",
        source={"src": "test"},
    )
    assert record.is_hidden is True
    assert record.display_ssid == "<Hidden SSID>"
    assert record.bssid == "aa:bb:cc:dd:ee:ff"


def test_deduplicate_prefers_stronger_signal_per_bssid():
    weak = normalize_record(
        ssid="A",
        bssid="00:11:22:33:44:55",
        channel=1,
        frequency_mhz=None,
        rssi_dbm=-80,
        signal_percent=None,
        security_raw="WPA2",
        interface_name="wlan0",
        source={},
    )
    strong = normalize_record(
        ssid="A",
        bssid="00:11:22:33:44:55",
        channel=1,
        frequency_mhz=None,
        rssi_dbm=-55,
        signal_percent=None,
        security_raw="WPA2",
        interface_name="wlan0",
        source={},
    )
    result = deduplicate_networks([weak, strong])
    assert len(result) == 1
    assert result[0].rssi_dbm == -55


def test_windows_parser_handles_partial_and_malformed_data():
    raw = """
SSID 1 : CorpNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
    Signal                  : 78%
    Channel                 : 11
SSID 2 :
    BSSID 1                 : invalid-mac
    Signal                  : x
"""
    parsed = parse_windows_netsh(raw)
    assert len(parsed) == 1
    assert parsed[0].ssid == "CorpNet"
    assert parsed[0].security_mode == "WPA2"


def test_linux_and_macos_parsers_from_mocked_output():
    linux_json = """[
      {"SSID":"Lab","BSSID":"aa:bb:cc:11:22:33","CHAN":"36","FREQ":"5180","SIGNAL":"70","SIGNAL_DBM":"-58","SECURITY":"WPA2 WPA3","DEVICE":"wlan0"}
    ]"""
    linux = parse_linux_nmcli_json(linux_json)
    assert linux[0].band == "5 GHz"
    assert linux[0].security_mode == "WPA2/WPA3"

    mac_raw = """
SSID BSSID             RSSI CHANNEL HT CC SECURITY
MyWiFi aa:bb:cc:dd:ee:ff -54 44 Y US WPA2(PSK/AES/AES)
"""
    mac = parse_macos_airport(mac_raw)
    assert mac[0].ssid == "MyWiFi"
    assert mac[0].channel == 44


def test_parser_malformed_json_returns_empty():
    assert parse_linux_nmcli_json("{not-json") == []
