from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from .constants import APP_SIZE, APP_TITLE, MAX_PACKET_LINES, SENSITIVE_DATA_NOTICE
from .models import DeviceRecord, InterfaceInfo, PacketRecord
from .privacy import mask_ip, mask_mac


class AnalyzerUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(APP_SIZE)

        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.StringVar(value="")

        top_notice = ttk.Label(
            self.root,
            text=f"Scope: LAN device discovery, packet capture, and basic security checks. {SENSITIVE_DATA_NOTICE}",
            foreground="#8a5a00",
            wraplength=840,
            justify="left",
        )
        top_notice.pack(fill="x", padx=10, pady=(8, 4))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=8)

        self._build_devices_tab()
        self._build_capture_tab()
        self._build_security_tab()

        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Label(status_frame, textvariable=self.status_var).pack(anchor="w")
        ttk.Label(status_frame, textvariable=self.progress_var).pack(anchor="w")

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
