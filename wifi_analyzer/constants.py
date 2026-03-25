"""Centralized configuration and static labels for the LAN analyzer."""

APP_TITLE = "WiFi Network Analyzer (LAN Features)"
APP_SIZE = "900x680"

UI_POLL_INTERVAL_MS = 120
MAX_PACKET_LINES = 1500

ARP_TIMEOUT_SECONDS = 1
SNIFF_SLICE_SECONDS = 1
SOCKET_TIMEOUT_SECONDS = 0.5

SECURITY_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
}
SECURITY_MAX_WORKERS = 30

INTERFACE_WIRELESS_KEYWORDS = (
    "wifi",
    "wi-fi",
    "wlan",
    "wireless",
    "airport",
)
INTERFACE_LAN_KEYWORDS = (
    "ethernet",
    "eth",
    "en",
    "lan",
)
INTERFACE_EXCLUDE_KEYWORDS = (
    "loopback",
    "lo",
    "vmware",
    "virtual",
    "vbox",
    "vpn",
    "tap",
    "docker",
    "hamachi",
)

SENSITIVE_DATA_NOTICE = (
    "Results may include sensitive local network metadata. "
    "Sharing raw output can expose endpoint details."
)
