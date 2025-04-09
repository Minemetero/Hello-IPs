import tkinter as tk
from tkinter import ttk, messagebox
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from .scanner import check_npcap, load_mac_prefixes, get_ip_range, scan_network
from .block import (block_via_arp_poison, block_via_arp_flood, block_via_arp_tornado, 
                    block_via_mac_flood, block_via_icmp_unreachable)
from .probe import probe_open_ports

class NetworkScannerApp:
    def __init__(self, master):
        self.master = master
        master.title("Hello-IPs: LAN Device Scanner")
        master.geometry("900x600")

        style = ttk.Style()
        style.theme_use("clam")

        header = tk.Label(master, text="Hello-IPs", font=("Helvetica", 20, "bold"))
        header.pack(pady=10)

        self.control_frame = tk.Frame(master)
        self.control_frame.pack(pady=5, fill="x", padx=20)
        
        self.scan_button = tk.Button(self.control_frame, text="Scan Network", command=self.run_scan, width=15)
        self.scan_button.grid(row=0, column=0, padx=5)
        
        tk.Label(self.control_frame, text="Block Method:").grid(row=0, column=1, padx=5)
        self.block_method_var = tk.StringVar(value="ARP Poisoning")
        # Updated to include five methods.
        methods = ["ARP Poisoning", "ARP Flooding", "ARP Tornado", "MAC Flooding", "ICMP Unreachable"]
        self.method_menu = tk.OptionMenu(self.control_frame, self.block_method_var, *methods)
        self.method_menu.config(width=15)
        self.method_menu.grid(row=0, column=2, padx=5)
        
        tk.Label(self.control_frame, text="Duration (s):").grid(row=0, column=3, padx=5)
        self.duration_var = tk.StringVar(value="60")
        self.duration_entry = tk.Entry(self.control_frame, textvariable=self.duration_var, width=7)
        self.duration_entry.grid(row=0, column=4, padx=5)
        
        self.block_button = tk.Button(self.control_frame, text="Block Selected Device", command=self.block_selected_device, width=20)
        self.block_button.grid(row=0, column=5, padx=5)

        self.probe_var = tk.BooleanVar(value=True)
        self.probe_checkbox = tk.Checkbutton(self.control_frame, text="Probe Open Ports", variable=self.probe_var)
        self.probe_checkbox.grid(row=0, column=6, padx=5)
        
        self.tip_label = tk.Label(master, text="", font=("Helvetica", 10, "italic"))
        self.tip_label.pack(pady=5)
        
        columns = ("IP Address", "MAC Address", "Vendor", "Device Name", "Open Ports")
        self.tree = ttk.Treeview(master, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180, anchor="center")
        self.tree.pack(expand=True, fill="both", padx=20, pady=10)
        
        self.network = None

    def run_scan(self):
        self.scan_button.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.tip_label.config(text="Scanning will take about two minutes, please be patient.")
        self.master.update()
        threading.Thread(target=self.thread_scan, daemon=True).start()

    def thread_scan(self):
        check_npcap()
        mac_prefix_path = os.path.join("data", "nmap-mac-prefixes.txt")
        mac_prefixes = load_mac_prefixes(mac_prefix_path)
        ip_range = get_ip_range()
        self.network = ip_range
        devices = scan_network(ip_range, mac_prefixes)
        # Probe open ports if enabled.
        if self.probe_var.get():
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_map = {executor.submit(probe_open_ports, device["ip"]): device for device in devices}
                for future in as_completed(future_map):
                    device = future_map[future]
                    try:
                        device["open_ports"] = future.result()
                    except Exception:
                        device["open_ports"] = []
        else:
            for device in devices:
                device["open_ports"] = []
        self.master.after(0, lambda: self.update_results(devices))

    def update_results(self, devices):
        for device in devices:
            ports = ",".join(map(str, device.get("open_ports", []))) if device.get("open_ports") else "None"
            self.tree.insert("", tk.END, values=(
                device.get("ip", "Unknown"),
                device.get("mac", "Unknown"),
                device.get("vendor", "Unknown"),
                device.get("device_name", "Unknown"),
                ports
            ))
        self.tip_label.config(text="")
        self.scan_button.config(state="normal")
        if not devices:
            messagebox.showinfo("Scan Complete", "No devices found on the network.")
        else:
            messagebox.showinfo("Scan Complete", f"Found {len(devices)} device(s).")

    def block_selected_device(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select a device to block.")
            return
        item = self.tree.item(selected)
        target_ip = item["values"][0]
        if not self.network:
            messagebox.showwarning("Error", "Network info unavailable. Please rescan.")
            return
        try:
            block_duration = int(self.duration_var.get())
        except ValueError:
            messagebox.showwarning("Input Error", "Enter a valid duration (in seconds).")
            return
        # Warn if an unstable method is chosen.
        if self.block_method_var.get() in ["ARP Tornado", "MAC Flooding", "ICMP Unreachable"]:
            warning = f"Warning: {self.block_method_var.get()} is experimental and may severely disrupt network communications. Continue?"
            if not messagebox.askyesno("Unstable Method Warning", warning):
                return
        confirm = messagebox.askyesno("Confirm Block", f"Block {target_ip} using {self.block_method_var.get()} for {block_duration} seconds?")
        if not confirm:
            return
        self.block_button.config(state="disabled")
        self.tip_label.config(text=f"Blocking {target_ip}... Please wait.")
        threading.Thread(target=self.thread_block, args=(target_ip, self.block_method_var.get(), block_duration), daemon=True).start()

    def thread_block(self, target_ip, block_method, block_duration):
        if block_method == "ARP Poisoning":
            block_via_arp_poison(target_ip, self.network, block_duration=block_duration)
        elif block_method == "ARP Flooding":
            block_via_arp_flood(target_ip, self.network, block_duration=block_duration)
        elif block_method == "ARP Tornado":
            block_via_arp_tornado(target_ip, self.network, block_duration=block_duration)
        elif block_method == "MAC Flooding":
            block_via_mac_flood(target_ip, self.network, block_duration=block_duration)
        elif block_method == "ICMP Unreachable":
            block_via_icmp_unreachable(target_ip, self.network, block_duration=block_duration)
        self.master.after(0, lambda: self.block_finished(target_ip))

    def block_finished(self, target_ip):
        self.tip_label.config(text="")
        self.block_button.config(state="normal")
        messagebox.showinfo("Block Finished", f"Blocking of {target_ip} is finished.")

def main():
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
