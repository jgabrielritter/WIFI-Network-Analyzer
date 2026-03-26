from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

from .constants import UI_POLL_INTERVAL_MS
from .dashboard_logic import compute_scan_summary, normalize_band_badge, normalize_security_chip
from .interfaces import annotate_with_latest, discover_interfaces, privilege_guidance
from .models import DeviceRecord, InterfaceInfo, PacketRecord, UIEvent
from .network_scan_service import NetworkScanService
from .packet_capture_service import PacketCaptureService
from .reports import (
    build_optimization_payload,
    export_comparison_csv,
    export_comparison_json,
    export_comparison_text,
    export_csv,
    export_json,
    export_optimization_csv,
    export_optimization_json,
    export_optimization_text,
    export_floorplan_html,
    export_floorplan_json,
    export_floorplan_text,
    export_text_report,
)
from .floorplan_models import FloorPlanLayout
from .room_map import FloorPlanStore
from .scan_history import ScanContext, ScanHistoryStore
from .security_checks import SecurityCheckService
from .ui import AnalyzerUI
from .wifi_analytics import WiFiAnalyticsEngine, WiFiAnalyticsReport, group_key_for_network
from .wifi_models import WiFiNetworkRecord
from .scan_comparison import compare_snapshots
from .trend_analysis import build_environment_score_trend
from .troubleshooting_engine import build_troubleshooting_summary
from .wifi_scan_service import WiFiScanService
from .visual_coverage_plan import FloorPlanCoverageReport, build_floor_plan_coverage, describe_ap_placement


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
        self.latest_optimization_payload: dict[str, object] | None = None
        self.floorplan_store = FloorPlanStore()
        self.active_plan: FloorPlanLayout = self.floorplan_store.create_plan(name="My Floor Plan")
        self.current_floorplan_report: FloorPlanCoverageReport | None = None
        self._canvas_item_to_entity: dict[int, tuple[str, str]] = {}
        self._drag_entity: tuple[str, str] | None = None
        self._background_image = None

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
        self.ui.bind_save_context(self._save_selected_context)
        self.ui.bind_compare_selected(self._compare_selected_snapshots)
        self.ui.set_wifi_table_sort_handlers(self._sort_networks)

        self.ui.export_current_json_button.configure(command=lambda: self._export(mode="current", fmt="json"))
        self.ui.export_current_csv_button.configure(command=lambda: self._export(mode="current", fmt="csv"))
        self.ui.export_history_json_button.configure(command=lambda: self._export(mode="history", fmt="json"))
        self.ui.export_history_csv_button.configure(command=lambda: self._export(mode="history", fmt="csv"))
        self.ui.export_history_txt_button.configure(command=lambda: self._export(mode="history", fmt="txt"))
        self.ui.export_comparison_json_button.configure(command=lambda: self._export(mode="comparison", fmt="json"))
        self.ui.export_comparison_csv_button.configure(command=lambda: self._export(mode="comparison", fmt="csv"))
        self.ui.export_comparison_txt_button.configure(command=lambda: self._export(mode="comparison", fmt="txt"))
        self.ui.export_optimization_json_button.configure(command=lambda: self._export(mode="optimization", fmt="json"))
        self.ui.export_optimization_csv_button.configure(command=lambda: self._export(mode="optimization", fmt="csv"))
        self.ui.export_optimization_txt_button.configure(command=lambda: self._export(mode="optimization", fmt="txt"))
        self.ui.bind_run_optimization(self._run_optimization_guidance)
        self.ui.floorplan_new_button.configure(command=self._new_floorplan)
        self.ui.floorplan_add_room_button.configure(command=self._add_floorplan_room)
        self.ui.floorplan_add_ap_button.configure(command=self._add_floorplan_ap_marker)
        self.ui.floorplan_load_image_button.configure(command=self._load_floorplan_background)
        self.ui.floorplan_save_button.configure(command=self._save_floorplan)
        self.ui.floorplan_load_button.configure(command=self._load_floorplan)
        self.ui.floorplan_render_button.configure(command=self._render_floorplan_coverage)
        self.ui.floorplan_export_json_button.configure(command=lambda: self._export_floorplan("json"))
        self.ui.floorplan_export_text_button.configure(command=lambda: self._export_floorplan("txt"))
        self.ui.floorplan_export_html_button.configure(command=lambda: self._export_floorplan("html"))
        self.ui.floorplan_canvas.bind("<ButtonPress-1>", self._on_floorplan_press)
        self.ui.floorplan_canvas.bind("<B1-Motion>", self._on_floorplan_drag)
        self.ui.floorplan_canvas.bind("<ButtonRelease-1>", lambda _evt: self._set_drag_entity(None))
        self._draw_floorplan()

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
        self.ui.set_context_inputs(snapshot.context.to_dict())
        self._render_networks(snapshot.networks, f"Viewing history snapshot: {snapshot.context.to_display_label()} | {snapshot.created_at}")
        self.ui.wifi_message_var.set(f"History view ({snapshot.source}) with {len(snapshot.networks)} networks.")
        self.ui.set_summary_cards(compute_scan_summary(snapshot.networks), snapshot.created_at, snapshot.interface_name)
        self.current_analytics = self.analytics_engine.build_report(snapshot.networks)
        self._render_analytics_summary(self.current_analytics)


    def _save_selected_context(self) -> None:
        idx = self.ui.selected_history_index()
        snapshots = self.history.list_snapshots()
        if idx is None or idx >= len(snapshots):
            messagebox.showinfo("Save Label Context", "Select a scan history entry first.")
            return

        source_snapshot = snapshots[idx]
        inputs = self.ui.get_context_inputs()
        context = ScanContext(
            scan_label=inputs.get("scan_label") or None,
            room_name=inputs.get("room_name") or None,
            location_name=inputs.get("location_name") or None,
            time_of_day_label=inputs.get("time_of_day_label") or None,
        )
        updated = self.history.update_context(source_snapshot.snapshot_id, context=context)
        if not updated:
            messagebox.showerror("Save Label Context", "Unable to update selected snapshot context.")
            return
        self.ui.set_history_items(self.history.list_snapshots())
        self.ui.status_var.set("Scan labeling context saved.")

    def _compare_selected_snapshots(self) -> None:
        idxs = self.ui.selected_history_indices()
        if len(idxs) < 2:
            messagebox.showinfo("Compare Snapshots", "Select exactly two history scans to compare.")
            return
        left_i, right_i = idxs[0], idxs[1]
        snapshots = self.history.list_snapshots()
        if max(left_i, right_i) >= len(snapshots):
            return

        left = snapshots[left_i]
        right = snapshots[right_i]
        target_ssid = self.ui.comparison_target_ssid()
        comparison = compare_snapshots(left, right, target_ssid=target_ssid)
        troubleshooting = build_troubleshooting_summary(comparison, target_ssid=target_ssid)

        env_trend = build_environment_score_trend([left, right])
        trend_line = f"Trend: {env_trend[0][1]} -> {env_trend[1][1]} ({env_trend[0][2]} -> {env_trend[1][2]})"
        lines = [
            f"Compared '{comparison.left.scan_label}' vs '{comparison.right.scan_label}'",
            f"Deltas: {comparison.deltas}",
        ]
        if comparison.findings:
            lines.append("Findings:")
            lines.extend([f"- {item}" for item in comparison.findings])
        lines.append(trend_line)
        lines.append("Troubleshooting:")
        lines.extend(troubleshooting)
        self.ui.set_comparison_insights(lines)

        self.ui.wifi_message_var.set(
            f"Comparison ready for '{comparison.left.scan_label}' vs '{comparison.right.scan_label}' (heuristic scan analysis)."
        )

    def _export_comparison(self, left: ScanSnapshot, right: ScanSnapshot, fmt: str, target_ssid: str | None) -> None:
        ext = {"json": ".json", "csv": ".csv", "txt": ".txt"}[fmt]
        path = filedialog.asksaveasfilename(
            title="Save Wi-Fi Comparison",
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
            initialfile="wifi_comparison_report",
        )
        if not path:
            return

        out_path = Path(path)
        if fmt == "json":
            export_comparison_json(out_path, left=left, right=right, target_ssid=target_ssid)
        elif fmt == "csv":
            export_comparison_csv(out_path, left=left, right=right, target_ssid=target_ssid)
        else:
            export_comparison_text(out_path, left=left, right=right, target_ssid=target_ssid)

    def _export(self, mode: str, fmt: str) -> None:
        snapshots = self.history.list_snapshots()
        if mode == "optimization":
            target_ssid = self.ui.optimization_target_ssid() or self.ui.comparison_target_ssid()
            if not target_ssid:
                messagebox.showinfo("Export", "Enter a target SSID for optimization exports.")
                return
            if not snapshots:
                messagebox.showinfo("Export", "Scan history is empty. Run a Wi-Fi scan first.")
                return
            self._export_optimization(snapshots=snapshots, fmt=fmt, target_ssid=target_ssid)
            self.ui.status_var.set("Optimization export successful.")
            return
        if mode == "comparison":
            idxs = self.ui.selected_history_indices()
            if len(idxs) < 2:
                messagebox.showinfo("Export", "Select two history scans to export a comparison.")
                return
            left, right = snapshots[idxs[0]], snapshots[idxs[1]]
            self._export_comparison(left=left, right=right, fmt=fmt, target_ssid=self.ui.comparison_target_ssid())
            self.ui.status_var.set("Comparison export successful.")
            return
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

    def _export_optimization(self, snapshots: list[ScanSnapshot], fmt: str, target_ssid: str) -> None:
        ext = {"json": ".json", "csv": ".csv", "txt": ".txt"}[fmt]
        path = filedialog.asksaveasfilename(
            title="Save Wi-Fi Optimization Plan",
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
            initialfile="wifi_optimization_plan",
        )
        if not path:
            return
        out_path = Path(path)
        if fmt == "json":
            export_optimization_json(out_path, snapshots=snapshots, target_ssid=target_ssid)
        elif fmt == "csv":
            export_optimization_csv(out_path, snapshots=snapshots, target_ssid=target_ssid)
        else:
            export_optimization_text(out_path, snapshots=snapshots, target_ssid=target_ssid)

    def _run_optimization_guidance(self) -> None:
        snapshots = self.history.list_snapshots()
        target_ssid = self.ui.optimization_target_ssid() or self.ui.comparison_target_ssid()
        if not target_ssid:
            messagebox.showinfo("Guided Optimization", "Enter the target SSID to optimize.")
            return
        if not snapshots:
            messagebox.showinfo("Guided Optimization", "Run and label scans across rooms before optimization.")
            return
        try:
            payload = build_optimization_payload(snapshots=snapshots, target_ssid=target_ssid)
            self.latest_optimization_payload = payload
            optimization = payload["optimization"]  # type: ignore[index]
            lines = [
                f"Target SSID: {payload['target_ssid']}",
                f"Confidence: {optimization['confidence_label']}",
                "",
                "Optimization summary:",
            ]
            lines.extend([f"- {item}" for item in optimization["summary_lines"]])
            lines.append("")
            lines.append("Priority rooms:")
            for item in optimization["improvement_plan"][:3]:
                lines.append(f"{item['priority_rank']}. {item['room_name']} [{item['priority_level']}] - {item['observed_issue']}")
            lines.append("")
            lines.append(f"Disclaimer: {payload['disclaimer']}")
            self.ui.set_optimization_summary(lines)
            self.ui.wifi_message_var.set(f"Optimization plan prepared for {target_ssid} across {payload['room_count']} room group(s).")
        except Exception as exc:
            messagebox.showerror("Guided Optimization", str(exc))

    def _new_floorplan(self) -> None:
        name = self.ui.floorplan_name_var.get().strip() or "Floor Plan"
        self.active_plan = self.floorplan_store.create_plan(name=name)
        self.current_floorplan_report = None
        self._draw_floorplan()
        self.ui.status_var.set(f"Created new floor plan: {name}")

    def _add_floorplan_room(self) -> None:
        name = simpledialog.askstring("Add Room", "Room name:")
        if not name:
            return
        x = 70 + ((len(self.active_plan.rooms) % 5) * 160)
        y = 80 + ((len(self.active_plan.rooms) // 5) * 110)
        room = self.floorplan_store.add_room(self.active_plan.plan_id, room_name=name, x=x, y=y)
        room.linked_labels = [name]
        self._draw_floorplan()
        self.ui.status_var.set(f"Added room '{room.room_name}'. Drag room boxes to reposition.")

    def _add_floorplan_ap_marker(self) -> None:
        label = simpledialog.askstring("Add AP Marker", "AP/router label:", initialvalue="Main AP")
        if not label:
            return
        x = 80 + (len(self.active_plan.ap_markers) * 80)
        marker = self.floorplan_store.add_ap_marker(self.active_plan.plan_id, label=label, x=x, y=50, marker_type="ap")
        self._draw_floorplan()
        self.ui.status_var.set(f"Added AP marker '{marker.label}'.")

    def _load_floorplan_background(self) -> None:
        path = filedialog.askopenfilename(
            title="Select floor-plan background image",
            filetypes=[("Image files", "*.png *.gif *.ppm *.pgm"), ("All files", "*.*")],
        )
        if not path:
            return
        self.active_plan.background_image_path = path
        self._draw_floorplan()

    def _save_floorplan(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save floor plan layout",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="floor_plan_layout.json",
        )
        if not path:
            return
        self.floorplan_store.save_to_file(self.active_plan.plan_id, Path(path))
        self.ui.status_var.set(f"Saved floor plan to {Path(path).name}.")

    def _load_floorplan(self) -> None:
        path = filedialog.askopenfilename(
            title="Load floor plan layout",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        self.active_plan = self.floorplan_store.load_from_file(Path(path))
        self.current_floorplan_report = None
        self._draw_floorplan()
        self.ui.status_var.set(f"Loaded floor plan '{self.active_plan.name}'.")

    def _render_floorplan_coverage(self) -> None:
        target = self.ui.floorplan_target_ssid()
        if not target:
            messagebox.showinfo("Floor Plan Coverage", "Enter a target SSID for map coverage mode.")
            return
        snapshots = self.history.list_snapshots()
        if not snapshots:
            messagebox.showinfo("Floor Plan Coverage", "Run Wi-Fi scans and label rooms before rendering coverage.")
            return
        self.current_floorplan_report = build_floor_plan_coverage(plan=self.active_plan, snapshots=snapshots, target_ssid=target)
        self._draw_floorplan()
        review = describe_ap_placement(plan=self.active_plan, report=self.current_floorplan_report)
        self.ui.set_floorplan_summary(self.current_floorplan_report.summary_lines + ["", "AP placement review:"] + [f"- {line}" for line in review] + ["", f"Disclaimer: {self.current_floorplan_report.disclaimer}"])
        self.ui.wifi_message_var.set(
            f"Visual coverage plan updated for '{target}' ({len(self.current_floorplan_report.room_states)} mapped rooms)."
        )

    def _export_floorplan(self, fmt: str) -> None:
        target = self.ui.floorplan_target_ssid()
        if not target:
            messagebox.showinfo("Export Visual Plan", "Enter target SSID first.")
            return
        snapshots = self.history.list_snapshots()
        if not snapshots:
            messagebox.showinfo("Export Visual Plan", "No scan history available.")
            return
        ext = {"json": ".json", "txt": ".txt", "html": ".html"}[fmt]
        path = filedialog.asksaveasfilename(
            title="Export visual coverage plan",
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
            initialfile="wifi_visual_coverage_plan",
        )
        if not path:
            return
        out_path = Path(path)
        if fmt == "json":
            export_floorplan_json(out_path, self.active_plan, snapshots, target)
        elif fmt == "html":
            export_floorplan_html(out_path, self.active_plan, snapshots, target)
        else:
            export_floorplan_text(out_path, self.active_plan, snapshots, target)
        self.ui.status_var.set(f"Visual plan export successful: {out_path.name}")

    def _draw_floorplan(self) -> None:
        canvas = self.ui.floorplan_canvas
        canvas.delete("all")
        self._canvas_item_to_entity.clear()
        if self.active_plan.background_image_path:
            try:
                self._background_image = tk.PhotoImage(file=self.active_plan.background_image_path)
                canvas.create_image(0, 0, image=self._background_image, anchor="nw")
            except Exception:
                self._background_image = None
                canvas.create_text(8, 8, text="Background image failed to load", anchor="nw", fill="#aa0000")

        status_by_room = {item.room_id: item for item in (self.current_floorplan_report.room_states if self.current_floorplan_report else [])}
        color = {
            "Strong coverage": "#b9e6b3",
            "Good coverage": "#d3efce",
            "Usable coverage": "#f8ecae",
            "Weak coverage": "#ffd59f",
            "Likely weak zone": "#ffb878",
            "Likely dead zone": "#ff9b9b",
            "Insufficient data": "#e0e0e0",
        }
        for room in self.active_plan.rooms:
            state = status_by_room.get(room.room_id)
            fill = color.get(state.status if state else "Insufficient data", "#e0e0e0")
            rect = canvas.create_rectangle(room.x, room.y, room.x + room.width, room.y + room.height, fill=fill, outline="#555", width=2)
            label_lines = [room.room_name]
            if state:
                label_lines.append(state.status)
                label_lines.append(f"#{state.priority_rank} | scans: {state.scan_count}")
            text = canvas.create_text(room.x + 8, room.y + 8, text="\\n".join(label_lines), anchor="nw", width=max(60, room.width - 16))
            self._canvas_item_to_entity[rect] = ("room", room.room_id)
            self._canvas_item_to_entity[text] = ("room", room.room_id)

        for marker in self.active_plan.ap_markers:
            oval = canvas.create_oval(marker.x - 8, marker.y - 8, marker.x + 8, marker.y + 8, fill="#4b6fff", outline="#1f2e7a")
            text = canvas.create_text(marker.x + 10, marker.y - 12, text=f"{marker.label} ({marker.marker_type})", anchor="nw", fill="#1f2e7a")
            self._canvas_item_to_entity[oval] = ("ap", marker.marker_id)
            self._canvas_item_to_entity[text] = ("ap", marker.marker_id)

    def _set_drag_entity(self, value: tuple[str, str] | None) -> None:
        self._drag_entity = value

    def _on_floorplan_press(self, event: tk.Event) -> None:
        item_ids = self.ui.floorplan_canvas.find_overlapping(event.x, event.y, event.x, event.y)
        entity = None
        for item_id in reversed(item_ids):
            entity = self._canvas_item_to_entity.get(item_id)
            if entity:
                break
        self._set_drag_entity(entity)
        if not entity:
            return
        entity_type, entity_id = entity
        if entity_type == "room" and self.current_floorplan_report:
            state = next((item for item in self.current_floorplan_report.room_states if item.room_id == entity_id), None)
            if state:
                lines = [
                    f"Room: {state.room_name}",
                    f"Status: {state.status}",
                    f"Strongest RSSI: {state.strongest_target_rssi_dbm}",
                    f"Strongest BSSID: {state.strongest_observed_bssid or 'N/A'}",
                    f"Dominant band: {state.dominant_band or 'N/A'}",
                    f"Security: {state.security_mode or 'N/A'}",
                    f"Latest scan: {state.latest_scan_at or 'N/A'}",
                    f"Evidence: {state.confidence_label} | scans={state.scan_count}",
                    f"Target present/absent: {state.target_present_count}/{state.target_absent_count}",
                    f"Priority: {state.priority_rank}",
                ]
                lines.extend([f"- {note}" for note in state.notes])
                self.ui.set_floorplan_room_details(lines)

    def _on_floorplan_drag(self, event: tk.Event) -> None:
        if not self._drag_entity:
            return
        entity_type, entity_id = self._drag_entity
        if entity_type == "room":
            self.floorplan_store.move_room(self.active_plan.plan_id, entity_id, x=event.x - 70, y=event.y - 45)
        elif entity_type == "ap":
            self.floorplan_store.move_ap_marker(self.active_plan.plan_id, entity_id, x=event.x, y=event.y)
        self._draw_floorplan()

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
