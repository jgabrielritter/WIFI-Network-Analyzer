from __future__ import annotations

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .netifaces_compat import netifaces

from .constants import SECURITY_MAX_WORKERS, SECURITY_PORTS, SOCKET_TIMEOUT_SECONDS
from .interfaces import resolve_interface_network
from .models import DeviceRecord, InterfaceInfo
from .privacy import mask_ip


class SecurityCheckService:
    def run(
        self,
        selected: InterfaceInfo,
        devices: list[DeviceRecord],
        cancel_event: threading.Event,
        on_progress: Callable[[str], None],
    ) -> list[str]:
        network = resolve_interface_network(selected)
        lines = [
            f"Scanning interface: {selected.name}",
            f"Network: {network}",
            f"Devices detected: {len(devices)}",
        ]

        if len(devices) > 10:
            lines.append("⚠️ Warning: unusually high number of devices detected.")

        interface_ip = selected.ipv4
        if interface_ip:
            iface_addr = ipaddress.ip_interface(f"{interface_ip}/{network.prefixlen}")
            if not iface_addr.ip.is_private:
                lines.append("⚠️ Warning: interface is not on a private IPv4 range.")

        gateway_info = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
        if not gateway_info or gateway_info[1] != selected.name:
            lines.append("⚠️ Warning: selected interface is not the active default gateway interface.")

        open_ports: list[str] = []
        futures = []
        with ThreadPoolExecutor(max_workers=SECURITY_MAX_WORKERS) as pool:
            for device in devices:
                for port, desc in SECURITY_PORTS.items():
                    if cancel_event.is_set():
                        break
                    futures.append(pool.submit(self._check_port, device.ip, port, desc))

            completed = 0
            total = max(len(futures), 1)
            for future in as_completed(futures):
                if cancel_event.is_set():
                    lines.append("Security scan cancelled.")
                    break
                result = future.result()
                completed += 1
                if result:
                    open_ports.append(result)
                if completed % 5 == 0 or completed == total:
                    on_progress(f"Security scan progress: {completed}/{total} checks")

        if open_ports:
            lines.append("Open ports detected (masked host):")
            lines.extend(open_ports)
        else:
            lines.append("No monitored common ports detected as open.")

        return lines

    @staticmethod
    def _check_port(ip_addr: str, port: int, desc: str) -> str | None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT_SECONDS)
            if sock.connect_ex((ip_addr, port)) == 0:
                return f"- {mask_ip(ip_addr)}: {port} ({desc})"
        return None
