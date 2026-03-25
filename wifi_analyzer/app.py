from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox

from .constants import UI_POLL_INTERVAL_MS
from .interfaces import annotate_with_latest, discover_interfaces, privilege_guidance
from .models import DeviceRecord, InterfaceInfo, PacketRecord, UIEvent
from .network_scan_service import NetworkScanService
from .packet_capture_service import PacketCaptureService
from .security_checks import SecurityCheckService
from .ui import AnalyzerUI


class WiFiNetworkAnalyzerApp:
    """UI controller that keeps Tk calls on the main thread using a queue."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.ui = AnalyzerUI(root)

        self.event_queue: queue.Queue[UIEvent] = queue.Queue()
        self.interfaces: list[InterfaceInfo] = []
        self.last_devices: list[DeviceRecord] = []

        self.network_scan_service = NetworkScanService()
        self.packet_capture_service = PacketCaptureService()
        self.security_service = SecurityCheckService()
        self.security_cancel = threading.Event()

        self._wire_actions()
        self._refresh_interfaces()
        self._poll_events()

    def _wire_actions(self) -> None:
        self.ui.scan_button.configure(command=self.start_network_scan)
        self.ui.capture_button.configure(command=self.start_packet_capture)
        self.ui.stop_capture_button.configure(command=self.stop_packet_capture)
        self.ui.security_button.configure(command=self.start_security_scan)
        self.ui.stop_security_button.configure(command=lambda: self.security_cancel.set())
        self.ui.refresh_interfaces_button.configure(command=self._refresh_interfaces)

    def _refresh_interfaces(self) -> None:
        self.interfaces = discover_interfaces()
        self.ui.set_interfaces(self.interfaces)
        self.ui.status_var.set(f"Found {len(self.interfaces)} IPv4 interfaces.")

    def _selected_interface(self) -> InterfaceInfo:
        selected_display = self.ui.selected_interface_display()
        for iface in self.interfaces:
            if iface.display_name == selected_display:
                return annotate_with_latest(iface)
        raise RuntimeError("Please select a valid network interface before starting.")

    def start_network_scan(self) -> None:
        try:
            selected = self._selected_interface()
        except Exception as exc:
            messagebox.showerror("Scan Error", str(exc))
            return

        self.ui.clear_devices()
        self.ui.status_var.set(f"Scanning {selected.name}...")
        self.ui.progress_var.set("")

        def _worker() -> None:
            try:
                network, devices = self.network_scan_service.scan_devices(selected)
                self.event_queue.put(UIEvent("scan_complete", {"network": network, "devices": devices, "interface": selected.name}))
            except Exception as exc:
                self.event_queue.put(UIEvent("error", {"title": "Scan Error", "message": f"{exc}\n{privilege_guidance()}"}))

        threading.Thread(target=_worker, daemon=True).start()

    def start_packet_capture(self) -> None:
        try:
            selected = self._selected_interface()
        except Exception as exc:
            messagebox.showerror("Capture Error", str(exc))
            return

        self.ui.clear_packet_output()
        self.ui.set_capture_running(True)
        self.ui.status_var.set(f"Capturing packets on {selected.name}...")

        started = self.packet_capture_service.start(
            selected=selected,
            redact=self.ui.redact_capture_var.get(),
            on_packet=lambda packet: self.event_queue.put(UIEvent("packet", {"packet": packet})),
            on_error=lambda msg: self.event_queue.put(UIEvent("error", {"title": "Capture Error", "message": f"{msg}\n{privilege_guidance()}"})),
        )
        if not started:
            self.ui.status_var.set("Packet capture is already running.")
            self.ui.set_capture_running(True)

    def stop_packet_capture(self) -> None:
        self.packet_capture_service.stop()
        self.ui.set_capture_running(False)
        self.ui.status_var.set("Packet capture stopped.")

    def start_security_scan(self) -> None:
        try:
            selected = self._selected_interface()
        except Exception as exc:
            messagebox.showerror("Security Scan Error", str(exc))
            return

        if not self.last_devices:
            messagebox.showinfo("Security Scan", "Run a LAN device scan first to build a target list.")
            return

        self.security_cancel.clear()
        self.ui.clear_security_output()
        self.ui.set_security_running(True)
        self.ui.status_var.set(f"Running security checks on {selected.name}...")

        def _worker() -> None:
            try:
                results = self.security_service.run(
                    selected=selected,
                    devices=self.last_devices,
                    cancel_event=self.security_cancel,
                    on_progress=lambda msg: self.event_queue.put(UIEvent("progress", {"message": msg})),
                )
                self.event_queue.put(UIEvent("security_complete", {"lines": results}))
            except Exception as exc:
                self.event_queue.put(UIEvent("error", {"title": "Security Scan Error", "message": f"{exc}\n{privilege_guidance()}"}))

        threading.Thread(target=_worker, daemon=True).start()

    def _poll_events(self) -> None:
        while True:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)
        self.root.after(UI_POLL_INTERVAL_MS, self._poll_events)

    def _handle_event(self, event: UIEvent) -> None:
        if event.event_type == "scan_complete":
            self.last_devices = event.payload["devices"]
            for device in self.last_devices:
                self.ui.add_device(device, redact=True)
            self.ui.status_var.set(
                f"Scan complete on {event.payload['interface']} ({event.payload['network']}): {len(self.last_devices)} devices found."
            )
        elif event.event_type == "packet":
            packet: PacketRecord = event.payload["packet"]
            self.ui.append_packet(packet)
        elif event.event_type == "security_complete":
            for line in event.payload["lines"]:
                self.ui.append_security_line(line)
            self.ui.set_security_running(False)
            self.ui.progress_var.set("")
            self.ui.status_var.set("Security checks complete.")
        elif event.event_type == "progress":
            self.ui.progress_var.set(event.payload["message"])
        elif event.event_type == "error":
            self.ui.set_capture_running(self.packet_capture_service.running)
            self.ui.set_security_running(False)
            self.ui.status_var.set("Operation failed.")
            messagebox.showerror(event.payload.get("title", "Error"), event.payload.get("message", "Unknown error"))


def main() -> None:
    root = tk.Tk()
    WiFiNetworkAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
