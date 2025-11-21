import ipaddress
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import netifaces
import scapy.all as scapy

class WiFiNetworkAnalyzer:
    def __init__(self, master):
        self.master = master
        master.title("WiFi Network Analyzer")
        master.geometry("800x600")

        # Create Notebook (Tabbed Interface)
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill='both')

        # Network Devices Tab
        self.devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.devices_frame, text="Network Devices")

        # Interface Selection
        self.interface_frame = ttk.Frame(self.devices_frame)
        self.interface_frame.pack(side='top', fill='x', padx=10, pady=10)

        ttk.Label(self.interface_frame, text="Select Network Interface:").pack(side='left')
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(
            self.interface_frame, 
            textvariable=self.interface_var, 
            state="readonly"
        )
        self.populate_interfaces()
        self.interface_dropdown.pack(side='left', padx=10)

        # Device Table
        self.device_columns = ('IP', 'MAC', 'Vendor')
        self.device_table = ttk.Treeview(
            self.devices_frame, 
            columns=self.device_columns, 
            show='headings'
        )
        for col in self.device_columns:
            self.device_table.heading(col, text=col)
            self.device_table.column(col, width=200)
        self.device_table.pack(expand=True, fill='both', padx=10, pady=10)

        # Scan Button
        self.scan_button = ttk.Button(
            self.devices_frame, 
            text="Scan Network", 
            command=self.start_network_scan
        )
        self.scan_button.pack(pady=10)

        # Packet Capture Tab
        self.packet_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.packet_frame, text="Packet Capture")

        self.packet_text = tk.Text(self.packet_frame, wrap='word', height=20)
        self.packet_text.pack(expand=True, fill='both', padx=10, pady=10)

        self.capture_button = ttk.Button(
            self.packet_frame,
            text="Capture Packets",
            command=self.start_packet_capture
        )
        self.capture_button.pack(pady=10)

        self.stop_capture_button = ttk.Button(
            self.packet_frame,
            text="Stop Capture",
            command=self.stop_packet_capture,
            state="disabled"
        )
        self.stop_capture_button.pack(pady=5)

        self.capture_stop_event = threading.Event()
        self.capture_thread = None
        self.capture_running = False

        # Security Scan Tab
        self.security_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.security_frame, text="Security Scan")

        self.security_text = tk.Text(self.security_frame, wrap='word', height=20)
        self.security_text.pack(expand=True, fill='both', padx=10, pady=10)

        self.security_button = ttk.Button(
            self.security_frame, 
            text="Run Security Scan", 
            command=self.run_security_scan
        )
        self.security_button.pack(pady=10)

    def populate_interfaces(self):
        """
        Populate network interfaces dropdown
        """
        wireless_interfaces = [
            iface for iface in netifaces.interfaces() 
            if iface.startswith(('wlan', 'wifi', 'wireless', 'en'))
        ]
        self.interface_dropdown['values'] = wireless_interfaces
        if wireless_interfaces:
            self.interface_dropdown.current(0)

    def start_network_scan(self):
        """
        Start network scan in a separate thread
        """
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showerror("Scan Error", "Please select a network interface before scanning.")
            return

        def scan_thread():
            try:
                # Clear existing entries
                for i in self.device_table.get_children():
                    self.device_table.delete(i)

                # Perform network scan
                network = self._get_interface_network(interface)
                arp_request = scapy.ARP(pdst=str(network))
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                clients = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                
                for element in clients:
                    ip = element[1].psrc
                    mac = element[1].hwsrc
                    vendor = self._get_vendor(mac)

                    self.device_table.insert('', 'end', values=(ip, mac, vendor))

            except Exception as e:
                messagebox.showerror("Scan Error", str(e))

        # Run scan in a separate thread
        threading.Thread(target=scan_thread, daemon=True).start()

    def start_packet_capture(self):
        """
        Capture network packets
        """
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showerror("Capture Error", "Please select a network interface before capturing packets.")
            return
        if self.capture_running:
            messagebox.showinfo("Capture Running", "Packet capture is already running.")
            return

        self.capture_stop_event.clear()
        self.capture_running = True
        self.capture_button.configure(state="disabled")
        self.stop_capture_button.configure(state="normal")
        self.packet_text.delete('1.0', tk.END)

        def capture_thread():
            def packet_handler(packet):
                if self.capture_stop_event.is_set():
                    return
                if packet.haslayer(scapy.IP):
                    packet_info = (
                        f"Time: {time.strftime('%H:%M:%S')} | "
                        f"SRC: {packet[scapy.IP].src} | "
                        f"DST: {packet[scapy.IP].dst} | "
                        f"Protocol: {packet[scapy.IP].proto}\n"
                    )
                    self.packet_text.insert(tk.END, packet_info)
                    self.packet_text.see(tk.END)

            try:
                while not self.capture_stop_event.is_set():
                    scapy.sniff(
                        iface=interface,
                        prn=packet_handler,
                        timeout=1,
                        stop_filter=lambda _: self.capture_stop_event.is_set(),
                        store=False
                    )
            except Exception as e:
                messagebox.showerror("Capture Error", str(e))
            finally:
                self.capture_running = False
                self.capture_button.configure(state="normal")
                self.stop_capture_button.configure(state="disabled")

        # Run capture in a separate thread
        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()

    def stop_packet_capture(self):
        """
        Stop the ongoing packet capture
        """
        if not self.capture_running:
            return
        self.capture_stop_event.set()

    def run_security_scan(self):
        """
        Perform basic network security scan
        """
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showerror("Security Scan Error", "Please select a network interface before running a security scan.")
            return
        self.security_text.delete('1.0', tk.END)

        def security_thread():
            try:
                # Network device count check
                network = self._get_interface_network(interface)
                arp_request = scapy.ARP(pdst=str(network))
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request

                clients = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                device_count = len(clients)

                security_checks = [
                    f"Scanning Interface: {interface}\n",
                    f"Network: {network}\n",
                    f"Total Devices Detected: {device_count}\n"
                ]

                if device_count > 10:
                    security_checks.append("⚠️ WARNING: Unusually high number of devices detected!\n")

                interface_ip = netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{}])[0].get('addr')
                if interface_ip:
                    ip_interface = ipaddress.ip_interface(f"{interface_ip}/{network.prefixlen}")
                    if not ip_interface.ip.is_private:
                        security_checks.append("⚠️ WARNING: Interface is not on a private network.\n")

                common_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS"}
                open_ports_report = []
                for element in clients:
                    ip_addr = element[1].psrc
                    ports_found = []
                    for port, desc in common_ports.items():
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(0.5)
                            if sock.connect_ex((ip_addr, port)) == 0:
                                ports_found.append(f"{port} ({desc})")
                    if ports_found:
                        open_ports_report.append(f"{ip_addr}: Open ports -> {', '.join(ports_found)}\n")

                if not open_ports_report:
                    security_checks.append("No common open ports detected on scanned devices.\n")
                else:
                    security_checks.append("Open ports detected:\n")
                    security_checks.extend(open_ports_report)

                gateway_info = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)
                if not gateway_info or gateway_info[1] != interface:
                    security_checks.append("⚠️ WARNING: No default gateway detected for this interface.\n")

                # Update security text
                for check in security_checks:
                    self.security_text.insert(tk.END, check)
            
            except Exception as e:
                self.security_text.insert(tk.END, f"Security Scan Error: {e}\n")
        
        # Run security scan in a separate thread
        threading.Thread(target=security_thread, daemon=True).start()

    def _get_vendor(self, mac_address: str) -> str:
        """
        Simplified MAC vendor lookup
        """
        try:
            from scapy.utils import oui_resolve

            vendor = oui_resolve(mac_address)
            if vendor:
                return vendor
        except Exception:
            pass

        try:
            normalized_mac = mac_address.replace('-', ':').upper()
            mac_prefix = normalized_mac.replace(':', '')[:6]
            vendor_map = {
                '000C29': 'VMware',
                '0050F2': 'Microsoft',
                '00163E': 'HP',
                '3C5A37': 'Google',
                'BC305B': 'Apple',
            }
            return vendor_map.get(mac_prefix, 'Unknown')
        except Exception:
            return 'Unknown'

    def _get_interface_network(self, interface: str) -> ipaddress.IPv4Network:
        """
        Resolve the IPv4 network for the selected interface
        """
        iface_info = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
        if not iface_info:
            raise RuntimeError(f"Interface '{interface}' has no IPv4 address.")

        ip_addr = iface_info[0].get('addr')
        netmask = iface_info[0].get('netmask')
        if not ip_addr or not netmask:
            raise RuntimeError(f"Interface '{interface}' is missing IP or netmask information.")

        return ipaddress.ip_interface(f"{ip_addr}/{netmask}").network

def main():
    root = tk.Tk()
    app = WiFiNetworkAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
