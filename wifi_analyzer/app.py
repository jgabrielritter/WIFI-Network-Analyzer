from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from .constants import UI_POLL_INTERVAL_MS
from .dashboard_logic import compute_scan_summary, normalize_band_badge, normalize_security_chip
from .interfaces import annotate_with_latest, discover_interfaces, privilege_guidance
from .models import DeviceRecord, InterfaceInfo, PacketRecord, UIEvent
from .network_scan_service import NetworkScanService
from .packet_capture_service import PacketCaptureService
from .reports import export_csv, export_json, export_text_report
from .scan_history import ScanHistoryStore
from .security_checks import SecurityCheckService
from .ui import AnalyzerUI
from .wifi_analytics import WiFiAnalyticsEngine, WiFiAnalyticsReport, group_key_for_network
from .wifi_models import WiFiNetworkRecord
from .wifi_scan_service import WiFiScanService


class WiFiNetworkAnalyzerApp:
    """UI controller that keeps Tk calls on the main thread using a queue."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.ui = AnalyzerUI(root)

        self.event_queue: queue.Queue[UIEvent] = queue.Queue()
        self.interfaces: list[InterfaceInfo] = []
        self.last_devices: list[DeviceRecord] = []
        self.current_networks: list[WiFiNetworkRecord] = []
        self.current_snapshot_id: str | None = None
        self.current_analytics: WiFiAnalyticsReport | None = None
        self.sort_key = "signal"
        self.sort_desc = True

        self.network_scan_service = NetworkScanService()
        self.packet_capture_service = PacketCaptureService()
        self.security_service = SecurityCheckService()
        self.wifi_service = WiFiScanService()
        self.history = ScanHistoryStore(max_entries=20)
        self.analytics_engine = WiFiAnalyticsEngine()
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
        self.ui.wifi_scan_button.configure(command=self.start_wifi_scan)
        self.ui.bind_wifi_selection(lambda _evt: self._on_wifi_selected())
        self.ui.bind_history_selection(lambda _evt: self._on_history_selected())
        self.ui.set_wifi_table_sort_handlers(self._sort_networks)

        self.ui.export_current_json_button.configure(command=lambda: self._export(mode="current", fmt="json"))
        self.ui.export_current_csv_button.configure(command=lambda: self._export(mode="current", fmt="csv"))
        self.ui.export_history_json_button.configure(command=lambda: self._export(mode="history", fmt="json"))
        self.ui.export_history_csv_button.configure(command=lambda: self._export(mode="history", fmt="csv"))
        self.ui.export_history_txt_button.configure(command=lambda: self._export(mode="history", fmt="txt"))

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

    def start_wifi_scan(self) -> None:
        self.ui.clear_wifi_networks()
        self.ui.set_wifi_scan_running(True)
        self.ui.set_selected_network_details(None)
        self.ui.wifi_message_var.set("Scanning nearby wireless networks...")
        self.ui.status_var.set("Running Wi-Fi scan...")

        def _worker() -> None:
            try:
                result = self.wifi_service.scan_networks()
                self.event_queue.put(UIEvent("wifi_scan_complete", {"result": result}))
            except Exception as exc:
                self.event_queue.put(UIEvent("error", {"title": "Wi-Fi Scan Error", "message": str(exc)}))

        threading.Thread(target=_worker, daemon=True).start()

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

    def _render_networks(self, networks: list[WiFiNetworkRecord], view_label: str) -> None:
        sorted_networks = self._apply_sort(networks)
        self.ui.set_wifi_networks(sorted_networks)
        self.ui.set_current_view_label(view_label)

    def _sort_networks(self, key: str) -> None:
        if self.sort_key == key:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_key = key
            self.sort_desc = True
        self._render_networks(self.current_networks, "Viewing: Current scan")

    def _apply_sort(self, networks: list[WiFiNetworkRecord]) -> list[WiFiNetworkRecord]:
        def key_fn(network: WiFiNetworkRecord):
            if self.sort_key == "signal":
                return network.rssi_dbm if network.rssi_dbm is not None else -1000
            if self.sort_key == "channel":
                return network.channel if network.channel is not None else 999
            if self.sort_key == "band":
                order = {"2.4 GHz": 1, "5 GHz": 2, "6 GHz": 3, "Unknown": 4}
                return order.get(normalize_band_badge(network.band), 9)
            if self.sort_key == "security":
                order = {"Open": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4, "WPA2/WPA3": 5, "Unknown": 6}
                return order.get(normalize_security_chip(network.security_mode), 9)
            if self.sort_key == "ssid":
                return network.display_ssid.lower()
            if self.sort_key == "bssid":
                return (network.bssid or "").lower()
            if self.sort_key == "last_seen":
                return network.scan_timestamp
            return network.display_ssid.lower()

        return sorted(networks, key=key_fn, reverse=self.sort_desc)

    def _on_wifi_selected(self) -> None:
        selected = self.ui.get_selected_wifi_network()
        first_seen = None
        group_rank = None
        strongest_in_group = None
        channel_congestion = None

        if selected and selected.bssid:
            history_items = self.history.list_snapshots()
            first = None
            for snapshot in reversed(history_items):
                for net in snapshot.networks:
                    if net.bssid and net.bssid == selected.bssid:
                        first = snapshot.created_at
                        break
            first_seen = first

        if selected and self.current_analytics:
            if selected.bssid:
                group_rank = self.current_analytics.network_rank_by_bssid.get(selected.bssid)
            group_key = group_key_for_network(selected, self.analytics_engine.config.hidden_ssid_group_name)
            strongest = self.current_analytics.strongest_bssid_by_group.get(group_key)
            strongest_in_group = (strongest == selected.bssid) if selected.bssid and strongest else False
            if selected.channel is not None:
                for channel in self.current_analytics.channel_congestion:
                    if channel.channel == selected.channel and channel.band == normalize_band_badge(selected.band):
                        channel_congestion = f"{channel.label} ({channel.network_count} observed)"
                        break

        self.ui.set_selected_network_details(
            selected,
            first_seen=first_seen,
            group_rank=group_rank,
            strongest_in_group=strongest_in_group,
            channel_congestion=channel_congestion,
        )

    def _on_history_selected(self) -> None:
        idx = self.ui.selected_history_index()
        snapshots = self.history.list_snapshots()
        if idx is None or idx >= len(snapshots):
            return
        snapshot = snapshots[idx]
        self._render_networks(snapshot.networks, f"Viewing history snapshot: {snapshot.created_at}")
        self.ui.wifi_message_var.set(f"History view ({snapshot.source}) with {len(snapshot.networks)} networks.")
        self.ui.set_summary_cards(compute_scan_summary(snapshot.networks), snapshot.created_at, snapshot.interface_name)
        self.current_analytics = self.analytics_engine.build_report(snapshot.networks)
        self._render_analytics_summary(self.current_analytics)

    def _export(self, mode: str, fmt: str) -> None:
        snapshots = self.history.list_snapshots()
        if mode == "current":
            if not snapshots:
                messagebox.showinfo("Export", "No current scan is available to export.")
                return
            snapshots = [snapshots[0]]

        if not snapshots:
            messagebox.showinfo("Export", "Scan history is empty. Run a Wi-Fi scan first.")
            return

        include_sensitive = not self.ui.redacted_export_var.get()
        warning = (
            "This export can include sensitive wireless metadata such as BSSID and SSID. "
            "Only share with trusted recipients."
            if include_sensitive
            else "Redacted mode masks BSSID values to reduce sensitivity."
        )
        if not messagebox.askyesno("Sensitive Data Warning", f"{warning}\n\nProceed with export?"):
            return

        ext = {"json": ".json", "csv": ".csv", "txt": ".txt"}[fmt]
        path = filedialog.asksaveasfilename(
            title="Save Wi-Fi Report",
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
            initialfile=f"wifi_report_{mode}",
        )
        if not path:
            return

        try:
            out_path = Path(path)
            redacted = self.ui.redacted_export_var.get()
            if fmt == "json":
                export_json(out_path, snapshots=snapshots, redacted=redacted)
            elif fmt == "csv":
                export_csv(out_path, snapshots=snapshots, redacted=redacted)
            else:
                export_text_report(out_path, snapshots=snapshots, redacted=redacted)
            self.ui.status_var.set(f"Export successful: {out_path.name}")
            self.ui.wifi_message_var.set(f"Exported {len(snapshots)} snapshot(s) to {out_path.name}.")
        except Exception as exc:
            self.ui.status_var.set("Export failed.")
            messagebox.showerror("Export Error", str(exc))

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
            self.ui.set_wifi_scan_running(False)
            self.ui.set_capture_running(self.packet_capture_service.running)
            self.ui.set_security_running(False)
            self.ui.status_var.set("Operation failed.")
            messagebox.showerror(event.payload.get("title", "Error"), event.payload.get("message", "Unknown error"))
        elif event.event_type == "wifi_scan_complete":
            result = event.payload["result"]
            networks = result.networks
            if self.ui.hide_hidden_var.get():
                networks = [item for item in networks if not item.is_hidden]

            self.current_networks = list(networks)
            snapshot = self.history.add_result(result)
            self.current_snapshot_id = snapshot.snapshot_id
            self.ui.set_history_items(self.history.list_snapshots())
            self._render_networks(self.current_networks, "Viewing: Current scan")
            self.ui.set_wifi_scan_running(False)

            summary = compute_scan_summary(self.current_networks)
            self.ui.set_summary_cards(summary, scan_time=snapshot.created_at, interface_name=result.interface_name)
            snapshots = self.history.list_snapshots()
            previous = snapshots[1] if len(snapshots) > 1 else None
            self.current_analytics = self.analytics_engine.build_report(
                self.current_networks,
                latest_snapshot=snapshot,
                previous_snapshot=previous,
            )
            self._render_analytics_summary(self.current_analytics)

            compare = self.history.compare_latest()
            if result.warning:
                self.ui.wifi_message_var.set(result.warning)
            elif not self.current_networks:
                self.ui.wifi_message_var.set("No Wi-Fi networks found.")
            elif compare:
                self.ui.wifi_message_var.set(
                    f"Found {len(self.current_networks)} networks via {result.source}. Δ New: {compare['new']}, Missing: {compare['missing']}."
                )
            else:
                self.ui.wifi_message_var.set(f"Found {len(self.current_networks)} networks via {result.source}.")
            self.ui.status_var.set("Wi-Fi scan complete.")

    def _render_analytics_summary(self, analytics: WiFiAnalyticsReport) -> None:
        top_channel = analytics.channel_congestion[0] if analytics.channel_congestion else None
        top_group = analytics.groups[0] if analytics.groups else None
        self.ui.summary_vars["env_score"].set(f"{analytics.environment.score} ({analytics.environment.label})")
        self.ui.summary_vars["top_channel"].set(
            f"CH {top_channel.channel} {top_channel.band} ({top_channel.label})" if top_channel else "N/A"
        )
        self.ui.summary_vars["top_group"].set(
            f"{top_group.ssid_display} ({top_group.access_point_count} APs)" if top_group else "N/A"
        )
        self.ui.set_analytics_insights(analytics.insights[:6])


def main() -> None:
    root = tk.Tk()
    WiFiNetworkAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
