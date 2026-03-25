from __future__ import annotations

from .scapy_compat import scapy

from .constants import ARP_TIMEOUT_SECONDS
from .interfaces import resolve_interface_network
from .models import DeviceRecord, InterfaceInfo
from .vendor_lookup import get_vendor


class NetworkScanService:
    """Performs ARP discovery for a selected interface."""

    def scan_devices(self, selected: InterfaceInfo) -> tuple[str, list[DeviceRecord]]:
        network = resolve_interface_network(selected)
        arp_request = scapy.ARP(pdst=str(network))
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        clients = scapy.srp(
            broadcast / arp_request,
            timeout=ARP_TIMEOUT_SECONDS,
            verbose=False,
        )[0]

        devices: list[DeviceRecord] = []
        for element in clients:
            ip = element[1].psrc
            mac = element[1].hwsrc
            devices.append(DeviceRecord(ip=ip, mac=mac, vendor=get_vendor(mac)))
        return str(network), devices
