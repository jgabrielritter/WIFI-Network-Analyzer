from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from .constants import APP_SIZE, APP_TITLE, MAX_PACKET_LINES, SENSITIVE_DATA_NOTICE
from .dashboard_logic import format_signal_cell, normalize_band_badge, security_chip_presentation
from .models import DeviceRecord, InterfaceInfo, PacketRecord
from .privacy import mask_ip, mask_mac
from .scan_history import ScanSnapshot
from .wifi_models import WiFiNetworkRecord


class AnalyzerUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1220x760" if APP_SIZE == "900x680" else APP_SIZE)

        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.StringVar(value="")
        self.wifi_message_var = tk.StringVar(value="Run a scan to view nearby wireless networks.")
        self.current_view_label_var = tk.StringVar(value="Viewing: Current scan")
        self.comparison_target_ssid_var = tk.StringVar(value="")
        self.scan_label_var = tk.StringVar(value="")
        self.room_name_var = tk.StringVar(value="")
        self.location_name_var = tk.StringVar(value="")
        self.time_of_day_var = tk.StringVar(value="")

        self._wifi_table_rows: dict[str, WiFiNetworkRecord] = {}

        top_notice = ttk.Label(
            self.root,
            text=f"Scope: Wi-Fi discovery/analysis + LAN device discovery, packet capture, and basic security checks. {SENSITIVE_DATA_NOTICE}",
            foreground="#8a5a00",
            wraplength=1120,
            justify="left",
        )
        top_notice.pack(fill="x", padx=10, pady=(8, 4))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=8)

        self._build_wifi_dashboard_tab()
        self._build_devices_tab()
        self._build_capture_tab()
        self._build_security_tab()

        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Label(status_frame, textvariable=self.status_var).pack(anchor="w")
        ttk.Label(status_frame, textvariable=self.progress_var).pack(anchor="w")

    def _build_wifi_dashboard_tab(self) -> None:
        self.wifi_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.wifi_frame, text="Wi-Fi Dashboard")

        top_controls = ttk.LabelFrame(self.wifi_frame, text="Scan Controls")
        top_controls.pack(fill="x", padx=4, pady=4)

        self.wifi_scan_button = ttk.Button(top_controls, text="Scan Wi-Fi Networks")
        self.wifi_scan_button.pack(side="left", padx=(8, 4), pady=6)
        self.hide_hidden_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top_controls, text="Hide hidden SSIDs", variable=self.hide_hidden_var).pack(side="left", padx=8)

        self.redacted_export_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top_controls, text="Redact BSSID in exports", variable=self.redacted_export_var).pack(side="left", padx=8)

        self.export_current_json_button = ttk.Button(top_controls, text="Export Current JSON")
        self.export_current_json_button.pack(side="right", padx=4)
        self.export_current_csv_button = ttk.Button(top_controls, text="Export Current CSV")
        self.export_current_csv_button.pack(side="right", padx=4)
        self.export_history_json_button = ttk.Button(top_controls, text="Export History JSON")
        self.export_history_json_button.pack(side="right", padx=4)
        self.export_history_csv_button = ttk.Button(top_controls, text="Export History CSV")
        self.export_history_csv_button.pack(side="right", padx=4)
        self.export_history_txt_button = ttk.Button(top_controls, text="Export Text Report")
        self.export_history_txt_button.pack(side="right", padx=4)
        self.export_comparison_json_button = ttk.Button(top_controls, text="Export Comparison JSON")
        self.export_comparison_json_button.pack(side="right", padx=4)
        self.export_comparison_csv_button = ttk.Button(top_controls, text="Export Comparison CSV")
        self.export_comparison_csv_button.pack(side="right", padx=4)
        self.export_comparison_txt_button = ttk.Button(top_controls, text="Export Comparison TXT")
        self.export_comparison_txt_button.pack(side="right", padx=4)

        summary_frame = ttk.LabelFrame(self.wifi_frame, text="Current Scan Summary")
        summary_frame.pack(fill="x", padx=4, pady=4)
        self.summary_vars = {
            "total": tk.StringVar(value="0"),
            "open": tk.StringVar(value="0"),
            "strongest": tk.StringVar(value="N/A"),
            "band_24": tk.StringVar(value="0"),
            "band_5": tk.StringVar(value="0"),
            "band_6": tk.StringVar(value="0"),
            "env_score": tk.StringVar(value="N/A"),
            "top_channel": tk.StringVar(value="N/A"),
            "top_group": tk.StringVar(value="N/A"),
            "scan_time": tk.StringVar(value="N/A"),
            "interface": tk.StringVar(value="N/A"),
        }
        cards = [
            ("Total", "total"),
            ("Open", "open"),
            ("Strongest", "strongest"),
            ("2.4 GHz", "band_24"),
            ("5 GHz", "band_5"),
            ("6 GHz", "band_6"),
            ("Env Score", "env_score"),
            ("Crowded CH", "top_channel"),
            ("Top SSID Group", "top_group"),
            ("Scan Time", "scan_time"),
            ("Interface", "interface"),
        ]
        for idx, (label, key) in enumerate(cards):
            cell = ttk.Frame(summary_frame)
            cell.grid(row=0, column=idx, padx=8, pady=6, sticky="w")
            ttk.Label(cell, text=label, foreground="#6a6a6a").pack(anchor="w")
            ttk.Label(cell, textvariable=self.summary_vars[key]).pack(anchor="w")

        ttk.Label(self.wifi_frame, textvariable=self.wifi_message_var, foreground="#444").pack(anchor="w", padx=8)
        ttk.Label(self.wifi_frame, textvariable=self.current_view_label_var, foreground="#444").pack(anchor="w", padx=8)

        body = ttk.Frame(self.wifi_frame)
        body.pack(expand=True, fill="both", padx=4, pady=4)
        body.columnconfigure(0, weight=4)
        body.columnconfigure(1, weight=2)

        results_wrap = ttk.LabelFrame(body, text="Network Results")
        results_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        results_wrap.rowconfigure(0, weight=1)
        results_wrap.columnconfigure(0, weight=1)

        columns = ("SSID", "BSSID", "Signal", "Channel", "Band", "Security", "Last Seen")
        self.wifi_table = ttk.Treeview(results_wrap, columns=columns, show="headings", height=14)
        for col in columns:
            self.wifi_table.heading(col, text=col)
            width = 110
            if col == "SSID":
                width = 230
            elif col == "Signal":
                width = 160
            elif col == "BSSID":
                width = 140
            elif col == "Last Seen":
                width = 180
            self.wifi_table.column(col, width=width, anchor="w")
        self.wifi_table.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(results_wrap, orient="vertical", command=self.wifi_table.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.wifi_table.configure(yscrollcommand=yscroll.set)

        self.wifi_table.tag_configure("band_24", background="#eef7ff")
        self.wifi_table.tag_configure("band_5", background="#f3fff0")
        self.wifi_table.tag_configure("band_6", background="#fff8e9")
        self.wifi_table.tag_configure("security_high", foreground="#8b0000")
        self.wifi_table.tag_configure("security_medium", foreground="#7b5d00")

        side_panel = ttk.Frame(body)
        side_panel.grid(row=0, column=1, sticky="nsew")
        side_panel.rowconfigure(0, weight=1)
        side_panel.rowconfigure(1, weight=1)
        side_panel.columnconfigure(0, weight=1)

        details = ttk.LabelFrame(side_panel, text="Selected Network Details")
        details.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        self.detail_vars = {k: tk.StringVar(value="N/A") for k in [
            "ssid", "hidden", "bssid", "signal", "quality", "channel", "frequency", "band", "security", "interface", "first_seen", "last_seen",
            "group_rank", "strongest_in_group", "channel_congestion", "notes"
        ]}
        rows = [
            ("SSID", "ssid"), ("Hidden", "hidden"), ("BSSID", "bssid"), ("Signal", "signal"), ("Quality", "quality"),
            ("Channel", "channel"), ("Frequency", "frequency"), ("Band", "band"), ("Security", "security"),
            ("Interface", "interface"), ("First Seen", "first_seen"), ("Last Seen", "last_seen"),
            ("SSID Rank", "group_rank"), ("Strongest AP", "strongest_in_group"), ("Channel Crowd", "channel_congestion"),
            ("Notes", "notes"),
        ]
        for i, (label, key) in enumerate(rows):
            ttk.Label(details, text=f"{label}:", foreground="#666").grid(row=i, column=0, sticky="nw", padx=6, pady=2)
            ttk.Label(details, textvariable=self.detail_vars[key], wraplength=330).grid(row=i, column=1, sticky="nw", padx=6, pady=2)

        history = ttk.LabelFrame(side_panel, text="Scan History (Session)")
        history.grid(row=1, column=0, sticky="nsew")
        ttk.Label(history, text="Session-only history. Not auto-saved to disk.", foreground="#666").pack(anchor="w", padx=6, pady=(4, 0))

        context_editor = ttk.Frame(history)
        context_editor.pack(fill="x", padx=6, pady=(4, 2))
        for idx, (label, var) in enumerate([
            ("Label", self.scan_label_var),
            ("Room", self.room_name_var),
            ("Location", self.location_name_var),
            ("Time", self.time_of_day_var),
        ]):
            ttk.Label(context_editor, text=label, foreground="#666").grid(row=idx, column=0, sticky="w", padx=(0, 4), pady=1)
            ttk.Entry(context_editor, textvariable=var).grid(row=idx, column=1, sticky="ew", pady=1)
        context_editor.columnconfigure(1, weight=1)
        self.save_context_button = ttk.Button(context_editor, text="Save Label Context")
        self.save_context_button.grid(row=0, column=2, rowspan=2, padx=(6, 0), sticky="nsew")

        compare_bar = ttk.Frame(history)
        compare_bar.pack(fill="x", padx=6, pady=(2, 2))
        ttk.Label(compare_bar, text="SSID focus:").pack(side="left")
        ttk.Entry(compare_bar, textvariable=self.comparison_target_ssid_var, width=18).pack(side="left", padx=(4, 8))
        self.compare_selected_button = ttk.Button(compare_bar, text="Compare Selected 2")
        self.compare_selected_button.pack(side="left")

        self.history_listbox = tk.Listbox(history, height=8, selectmode=tk.EXTENDED)
        self.history_listbox.pack(expand=True, fill="both", padx=6, pady=6)
        self.analytics_insights = tk.Text(history, wrap="word", height=6)
        self.analytics_insights.pack(fill="x", padx=6, pady=(0, 6))
        self.comparison_insights = tk.Text(history, wrap="word", height=8)
        self.comparison_insights.pack(fill="x", padx=6, pady=(0, 6))

    def _build_devices_tab(self) -> None:
        self.devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.devices_frame, text="LAN Devices")

        interface_frame = ttk.Frame(self.devices_frame)
        interface_frame.pack(fill="x", pady=6)

        ttk.Label(interface_frame, text="Select active interface:").pack(side="left")
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(interface_frame, textvariable=self.interface_var, state="readonly", width=70)
        self.interface_dropdown.pack(side="left", padx=8)

        self.refresh_interfaces_button = ttk.Button(interface_frame, text="Refresh Interfaces")
        self.refresh_interfaces_button.pack(side="left", padx=4)

        self.scan_button = ttk.Button(self.devices_frame, text="Scan LAN Devices")
        self.scan_button.pack(anchor="w", pady=4)

        columns = ("IP", "MAC", "Vendor")
        self.device_table = ttk.Treeview(self.devices_frame, columns=columns, show="headings", height=14)
        for col in columns:
            self.device_table.heading(col, text=col)
            self.device_table.column(col, width=260)
        self.device_table.pack(expand=True, fill="both", pady=6)

    def _build_capture_tab(self) -> None:
        self.capture_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.capture_frame, text="Packet Capture")

        controls = ttk.Frame(self.capture_frame)
        controls.pack(fill="x", pady=4)

        self.capture_button = ttk.Button(controls, text="Start Capture")
        self.capture_button.pack(side="left")
        self.stop_capture_button = ttk.Button(controls, text="Stop Capture", state="disabled")
        self.stop_capture_button.pack(side="left", padx=6)

        self.redact_capture_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls, text="Mask packet endpoints", variable=self.redact_capture_var).pack(side="left", padx=12)

        self.packet_text = tk.Text(self.capture_frame, wrap="word", height=24)
        self.packet_text.pack(expand=True, fill="both", pady=6)

    def _build_security_tab(self) -> None:
        self.security_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.security_frame, text="Security Checks")

        controls = ttk.Frame(self.security_frame)
        controls.pack(fill="x", pady=4)
        self.security_button = ttk.Button(controls, text="Run Security Checks")
        self.security_button.pack(side="left")
        self.stop_security_button = ttk.Button(controls, text="Cancel", state="disabled")
        self.stop_security_button.pack(side="left", padx=6)

        self.security_text = tk.Text(self.security_frame, wrap="word", height=24)
        self.security_text.pack(expand=True, fill="both", pady=6)

    def set_interfaces(self, items: list[InterfaceInfo]) -> None:
        values = [item.display_name for item in items]
        self.interface_dropdown["values"] = values
        if values:
            self.interface_dropdown.current(0)

    def selected_interface_display(self) -> str:
        return self.interface_var.get().strip()

    def clear_devices(self) -> None:
        for row in self.device_table.get_children():
            self.device_table.delete(row)

    def set_wifi_table_sort_handlers(self, on_sort: callable) -> None:
        columns = ("SSID", "BSSID", "Signal", "Channel", "Band", "Security", "Last Seen")
        keys = {
            "SSID": "ssid",
            "BSSID": "bssid",
            "Signal": "signal",
            "Channel": "channel",
            "Band": "band",
            "Security": "security",
            "Last Seen": "last_seen",
        }
        for col in columns:
            self.wifi_table.heading(col, text=col, command=lambda k=keys[col]: on_sort(k))

    def clear_wifi_networks(self) -> None:
        self._wifi_table_rows.clear()
        for row in self.wifi_table.get_children():
            self.wifi_table.delete(row)

    def set_wifi_networks(self, networks: list[WiFiNetworkRecord]) -> None:
        self.clear_wifi_networks()
        for idx, network in enumerate(networks):
            row_id = f"row-{idx}"
            self._wifi_table_rows[row_id] = network
            band = normalize_band_badge(network.band)
            sec = security_chip_presentation(network.security_mode)
            tags = []
            if band == "2.4 GHz":
                tags.append("band_24")
            elif band == "5 GHz":
                tags.append("band_5")
            elif band == "6 GHz":
                tags.append("band_6")
            if sec.risk_level == "high":
                tags.append("security_high")
            elif sec.risk_level == "medium":
                tags.append("security_medium")
            self.wifi_table.insert(
                "",
                "end",
                iid=row_id,
                values=(
                    network.display_ssid,
                    network.bssid or "N/A",
                    format_signal_cell(network),
                    network.channel if network.channel is not None else "N/A",
                    band,
                    sec.chip,
                    network.scan_timestamp,
                ),
                tags=tuple(tags),
            )

    def get_selected_wifi_network(self) -> WiFiNetworkRecord | None:
        selected = self.wifi_table.selection()
        if not selected:
            return None
        return self._wifi_table_rows.get(selected[0])

    def bind_wifi_selection(self, callback: callable) -> None:
        self.wifi_table.bind("<<TreeviewSelect>>", callback)

    def set_selected_network_details(
        self,
        network: WiFiNetworkRecord | None,
        first_seen: str | None = None,
        group_rank: int | None = None,
        strongest_in_group: bool | None = None,
        channel_congestion: str | None = None,
    ) -> None:
        if network is None:
            for var in self.detail_vars.values():
                var.set("N/A")
            return
        self.detail_vars["ssid"].set(network.display_ssid)
        self.detail_vars["hidden"].set("Yes" if network.is_hidden else "No")
        self.detail_vars["bssid"].set(network.bssid or "N/A")
        self.detail_vars["signal"].set(format_signal_cell(network))
        self.detail_vars["quality"].set(network.signal_quality_label)
        self.detail_vars["channel"].set(str(network.channel) if network.channel is not None else "N/A")
        self.detail_vars["frequency"].set(f"{network.frequency_mhz} MHz" if network.frequency_mhz is not None else "N/A")
        self.detail_vars["band"].set(normalize_band_badge(network.band))
        self.detail_vars["security"].set(security_chip_presentation(network.security_mode).chip)
        self.detail_vars["interface"].set(network.interface_name or "Unknown")
        self.detail_vars["first_seen"].set(first_seen or network.scan_timestamp)
        self.detail_vars["last_seen"].set(network.scan_timestamp)
        self.detail_vars["group_rank"].set(str(group_rank) if group_rank is not None else "N/A")
        if strongest_in_group is None:
            self.detail_vars["strongest_in_group"].set("N/A")
        else:
            self.detail_vars["strongest_in_group"].set("Yes" if strongest_in_group else "No")
        self.detail_vars["channel_congestion"].set(channel_congestion or "N/A")
        self.detail_vars["notes"].set(
            "Some fields depend on OS scanner support. Unknown values are reported as-is."
        )

    def set_summary_cards(self, summary: dict[str, str], scan_time: str, interface_name: str | None) -> None:
        for key, value in summary.items():
            if key in self.summary_vars:
                self.summary_vars[key].set(value)
        self.summary_vars["scan_time"].set(scan_time)
        self.summary_vars["interface"].set(interface_name or "Unknown")

    def set_current_view_label(self, text: str) -> None:
        self.current_view_label_var.set(text)

    def set_history_items(self, snapshots: list[ScanSnapshot]) -> None:
        self.history_listbox.delete(0, tk.END)
        for item in snapshots:
            self.history_listbox.insert(tk.END, f"{item.created_at} | {len(item.networks)} networks | {item.context.to_display_label()}")

    def bind_history_selection(self, callback: callable) -> None:
        self.history_listbox.bind("<<ListboxSelect>>", callback)

    def bind_save_context(self, callback: callable) -> None:
        self.save_context_button.configure(command=callback)

    def bind_compare_selected(self, callback: callable) -> None:
        self.compare_selected_button.configure(command=callback)

    def selected_history_index(self) -> int | None:
        selected = self.history_listbox.curselection()
        return selected[0] if selected else None

    def selected_history_indices(self) -> list[int]:
        return list(self.history_listbox.curselection())

    def get_context_inputs(self) -> dict[str, str]:
        return {
            "scan_label": self.scan_label_var.get().strip(),
            "room_name": self.room_name_var.get().strip(),
            "location_name": self.location_name_var.get().strip(),
            "time_of_day_label": self.time_of_day_var.get().strip(),
        }

    def set_context_inputs(self, context: dict[str, str | None]) -> None:
        self.scan_label_var.set(context.get("scan_label") or "")
        self.room_name_var.set(context.get("room_name") or "")
        self.location_name_var.set(context.get("location_name") or "")
        self.time_of_day_var.set(context.get("time_of_day_label") or "")

    def comparison_target_ssid(self) -> str | None:
        value = self.comparison_target_ssid_var.get().strip()
        return value or None

    def add_device(self, device: DeviceRecord, redact: bool = True) -> None:
        ip = mask_ip(device.ip) if redact else device.ip
        mac = mask_mac(device.mac) if redact else device.mac
        self.device_table.insert("", "end", values=(ip, mac, device.vendor))

    def append_packet(self, packet: PacketRecord) -> None:
        text = f"Time: {packet.timestamp} | SRC: {packet.src} | DST: {packet.dst} | Protocol: {packet.protocol}\n"
        self.packet_text.insert(tk.END, text)
        if int(self.packet_text.index("end-1c").split(".")[0]) > MAX_PACKET_LINES:
            self.packet_text.delete("1.0", "2.0")
        self.packet_text.see(tk.END)

    def clear_packet_output(self) -> None:
        self.packet_text.delete("1.0", tk.END)

    def clear_security_output(self) -> None:
        self.security_text.delete("1.0", tk.END)

    def append_security_line(self, line: str) -> None:
        self.security_text.insert(tk.END, f"{line}\n")
        self.security_text.see(tk.END)

    def set_capture_running(self, running: bool) -> None:
        self.capture_button.configure(state="disabled" if running else "normal")
        self.stop_capture_button.configure(state="normal" if running else "disabled")

    def set_security_running(self, running: bool) -> None:
        self.security_button.configure(state="disabled" if running else "normal")
        self.stop_security_button.configure(state="normal" if running else "disabled")

    def set_wifi_scan_running(self, running: bool) -> None:
        self.wifi_scan_button.configure(state="disabled" if running else "normal")

    def set_analytics_insights(self, lines: list[str]) -> None:
        self.analytics_insights.delete("1.0", tk.END)
        for line in lines:
            self.analytics_insights.insert(tk.END, f"- {line}\n")

    def set_comparison_insights(self, lines: list[str]) -> None:
        self.comparison_insights.delete("1.0", tk.END)
        for line in lines:
            self.comparison_insights.insert(tk.END, f"{line}\n")
