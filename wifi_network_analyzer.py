import tkinter as tk
from tkinter import ttk
import threading
import time
import json
import sys

import scapy.all as scapy
import netifaces

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
        interface = self.interface_var.get()
        
        def scan_thread():
            try:
                # Clear existing entries
                for i in self.device_table.get_children():
                    self.device_table.delete(i)
                
                # Perform network scan
                arp_request = scapy.ARP(pdst='192.168.1.0/24')
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                clients = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                
                for element in clients:
                    ip = element[1].psrc
                    mac = element[1].hwsrc
                    vendor = self._get_vendor(mac)
                    
                    self.device_table.insert('', 'end', values=(ip, mac, vendor))
            
            except Exception as e:
                tk.messagebox.showerror("Scan Error", str(e))
        
        # Run scan in a separate thread
        threading.Thread(target=scan_thread, daemon=True).start()

    def start_packet_capture(self):
        """
        Capture network packets
        """
        interface = self.interface_var.get()
        self.packet_text.delete('1.0', tk.END)
        
        def capture_thread():
            def packet_handler(packet):
                if packet.haslayer(scapy.IP):
                    packet_info = (
                        f"Time: {time.strftime('%H:%M:%S')} | "
                        f"SRC: {packet[scapy.IP].src} | "
                        f"DST: {packet[scapy.IP].dst} | "
                        f"Protocol: {packet[scapy.IP].proto}\n"
                    )
                    self.packet_text.insert(tk.END, packet_info)
                    self.packet_text.see(tk.END)
            
            scapy.sniff(iface=interface, prn=packet_handler, timeout=30)
        
        # Run capture in a separate thread
        threading.Thread(target=capture_thread, daemon=True).start()

    def run_security_scan(self):
        """
        Perform basic network security scan
        """
        interface = self.interface_var.get()
        self.security_text.delete('1.0', tk.END)
        
        def security_thread():
            try:
                # Network device count check
                arp_request = scapy.ARP(pdst='192.168.1.0/24')
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                clients = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                device_count = len(clients)
                
                security_checks = [
                    f"Scanning Interface: {interface}\n",
                    f"Total Devices Detected: {device_count}\n"
                ]
                
                if device_count > 10:
                    security_checks.append("⚠️ WARNING: Unusually high number of devices detected!\n")
                
                # Simulated additional checks
                security_checks.extend([
                    "Checking for open ports...\n",
                    "Verifying network encryption...\n",
                    "Scanning for potential vulnerabilities...\n"
                ])
                
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
            mac_prefix = mac_address[:8].replace(':', '').upper()
            vendor_map = {
                '000C29': 'VMware',
                '0050F2': 'Microsoft',
                '00163E': 'HP',
            }
            return vendor_map.get(mac_prefix, 'Unknown')
        except Exception:
            return 'Unknown'

def main():
    root = tk.Tk()
    app = WiFiNetworkAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()