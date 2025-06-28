import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from .scanner import check_npcap, load_mac_prefixes, get_ip_range, scan_network, get_mac_vendor, logger
from .block import (block_via_arp_poison, block_via_arp_flood, block_via_arp_tornado,
                    block_via_mac_flood, block_via_icmp_unreachable, block_via_tcp_syn_flood,
                    block_via_dns_amplification)
from .probe import probe_open_ports, fingerprint_os
from .utils import save_scan_results, FileViewer
from .utils.log_saver import export_logs

class NetworkScannerApp:
    def __init__(self, master):
        self.master = master
        master.configure(bg="white")
        master.geometry("1000x800")
        master.minsize(1100, 600)
        master.title("Hello-IPs: LAN Device Scanner")
        master.resizable(True, True)

        # Use Style for Ttk components if desired
        style = ttk.Style()
        style.theme_use("clam")

        # Track whether we show vendor / ports / OS columns
        self.show_vendor_var = tk.BooleanVar(value=True)
        self.show_port_var = tk.BooleanVar(value=True)
        self.show_os_var = tk.BooleanVar(value=True)

        # Data storage
        self.network = None
        self.current_devices = []
        self.mac_prefixes = {}

        # Set up logger callback
        logger.set_status_callback(self.update_status)

        # Create menus (File, Options, Help)
        self.create_menu()

        # Header frame (tk, not ttk) to remove gray background
        self.header_frame = tk.Frame(master, bg="white")
        self.header_frame.pack(fill="x", padx=10, pady=10)

        # "Hello-IPs" title
        self.header_label = tk.Label(
            self.header_frame, 
            text="Hello-IPs", 
            font=("Helvetica", 20, "bold"),
            bg="white"  # match frame bg
        )
        self.header_label.pack(expand=True)
        self.header_label.configure(anchor="center", justify="center")

        # Top controls frame (tk, not ttk) so background is white
        self.top_control_frame = tk.Frame(master, bg="white")
        self.top_control_frame.pack(fill="x", padx=10, pady=5)
        self.create_top_controls(self.top_control_frame)

        # Main content frame
        self.main_frame = tk.Frame(master, bg="white")
        self.main_frame.pack(expand=True, fill="both", padx=10, pady=5)
        # Column 0 is the treeview, column 1 is the blocking panel
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=0)

        self.create_treeview(self.main_frame)
        self.create_blocking_panel(self.main_frame)

        # Status bar at the bottom
        self.status_bar = ttk.Label(master, text="Ready", relief="sunken", anchor="w")
        self.status_bar.pack(side="bottom", fill="x")

        self.master.update_idletasks()

    def create_menu(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_command(label="Open File", command=self.view_saved_results)
        file_menu.add_separator()
        file_menu.add_command(label="Export Logs", command=lambda: export_logs(self.master))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Options menu: checkbuttons to toggle Vendor and Open Ports columns
        options_menu = tk.Menu(menubar, tearoff=0)
        options_menu.add_checkbutton(
            label="Vendor Column",
            variable=self.show_vendor_var,
            command=self.update_treeview_columns
        )
        options_menu.add_checkbutton(
            label="Open Ports Column",
            variable=self.show_port_var,
            command=self.update_treeview_columns
        )
        options_menu.add_checkbutton(
            label="OS Guess Column",
            variable=self.show_os_var,
            command=self.update_treeview_columns
        )
        menubar.add_cascade(label="Options", menu=options_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Support", command=self.show_support)
        menubar.add_cascade(label="Help", menu=help_menu)

    def show_about(self):
        messagebox.showinfo("About", "Hello-IPs LAN Device Scanner\nDeveloper: Minemetero")

    def show_support(self):
        import webbrowser
        webbrowser.open("https://github.com/Minemetero/Hello-IPs/issues")
        messagebox.showinfo("Support", "Opening GitHub Issues page.")

    def create_top_controls(self, parent):
        self.scan_button = ttk.Button(parent, text="Scan", command=self.run_scan)
        self.scan_button.grid(row=0, column=0, padx=5, pady=5)

        self.save_button = ttk.Button(parent, text="Save Results", command=self.save_results)
        self.save_button.grid(row=0, column=1, padx=5, pady=5)

        parent.columnconfigure(2, weight=1)

    def create_treeview(self, parent):
        # Container for the treeview + scrollbar
        results_container = ttk.Frame(parent)
        results_container.grid(row=0, column=0, sticky="nsew")
        parent.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(results_container, show="headings", selectmode="browse")
        self.tree.pack(expand=True, fill="both", side="left")

        scrollbar = ttk.Scrollbar(results_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Initialize columns based on vendor/port toggles
        self.update_treeview_columns()

    def create_blocking_panel(self, parent):
        # Fixed width and a reasonable height to ensure visibility
        self.blocking_panel = ttk.Frame(parent, relief="groove", borderwidth=2, width=300, height=400)
        self.blocking_panel.grid(row=0, column=1, sticky="ns", padx=(10, 0))
        self.blocking_panel.grid_propagate(False)

        # Configure grid columns inside the blocking panel for even spacing
        self.blocking_panel.grid_columnconfigure(0, weight=1)
        self.blocking_panel.grid_columnconfigure(1, weight=1)

        # Row 0: "Blocking" heading
        heading_frame = ttk.Frame(self.blocking_panel)
        heading_frame.grid(row=0, column=0, columnspan=2, pady=(10, 15))
        heading_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(heading_frame, text="Blocking", font=("Helvetica", 14, "bold")).grid(row=0, column=0)

        # Row 1: "Block Method" label & OptionMenu
        ttk.Label(self.blocking_panel, text="Block Method:").grid(row=1, column=0, sticky="e", padx=(5, 2), pady=5)
        self.block_method_var = tk.StringVar(value="ARP Poisoning")
        methods = ["ARP Poisoning", "ARP Flooding", "ARP Tornado", "MAC Flooding", "ICMP Unreachable",
                  "TCP SYN Flood", "DNS Amplification"]
        self.method_menu = ttk.OptionMenu(self.blocking_panel, self.block_method_var, methods[0], *methods)
        self.method_menu.grid(row=1, column=1, sticky="w", padx=(2, 5), pady=5)

        # Row 2: "Duration (s):" label & entry
        ttk.Label(self.blocking_panel, text="Duration (s):").grid(row=2, column=0, sticky="e", padx=(5, 2), pady=5)
        self.duration_var = tk.StringVar(value="60")
        self.duration_entry = ttk.Entry(self.blocking_panel, textvariable=self.duration_var, width=10)
        self.duration_entry.grid(row=2, column=1, sticky="w", padx=(2, 5), pady=5)

        # Row 3: Additional parameters for TCP SYN Flood and DNS Amplification
        self.param_frame = ttk.Frame(self.blocking_panel)
        self.param_frame.grid(row=3, column=0, columnspan=2, pady=5)
        
        # TCP SYN Flood parameters
        self.tcp_port_label = ttk.Label(self.param_frame, text="Target Port:")
        self.tcp_port_var = tk.StringVar(value="80")
        self.tcp_port_entry = ttk.Entry(self.param_frame, textvariable=self.tcp_port_var, width=10)
        
        # DNS Amplification parameters
        self.dns_server_label = ttk.Label(self.param_frame, text="DNS Server:")
        self.dns_server_var = tk.StringVar(value="8.8.8.8")
        self.dns_server_entry = ttk.Entry(self.param_frame, textvariable=self.dns_server_var, width=15)
        
        # Hide parameters initially
        self.tcp_port_label.grid_remove()
        self.tcp_port_entry.grid_remove()
        self.dns_server_label.grid_remove()
        self.dns_server_entry.grid_remove()
        
        # Update parameters visibility when method changes
        self.block_method_var.trace_add("write", self.update_block_parameters)

        # Row 4: "Block Device" button
        button_frame = ttk.Frame(self.blocking_panel)
        button_frame.grid(row=4, column=0, columnspan=2, pady=(15, 10))
        button_frame.grid_columnconfigure(0, weight=1)
        self.block_button = ttk.Button(button_frame, text="Block Device", command=self.block_selected_device)
        self.block_button.grid(row=0, column=0)

    # ----------------------- Treeview Columns -----------------------
    def update_treeview_columns(self):
        # Decide which columns appear
        columns = ["IP Address", "MAC Address"]
        if self.show_vendor_var.get():
            columns.append("Vendor")
        columns.append("Device Name")
        if self.show_os_var.get():
            columns.append("OS Guess")
        if self.show_port_var.get():
            columns.append("Open Ports")

        self.tree["columns"] = columns

        # Set default width and minwidth for each column
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "IP Address":
                self.tree.column(col, anchor="center", stretch=True, width=110, minwidth=90)
            elif col == "MAC Address":
                self.tree.column(col, anchor="center", stretch=True, width=140, minwidth=100)
            elif col == "Vendor":
                self.tree.column(col, anchor="center", stretch=True, width=140, minwidth=100)
            elif col == "Device Name":
                self.tree.column(col, anchor="center", stretch=True, width=140, minwidth=100)
            elif col == "OS Guess":
                self.tree.column(col, anchor="center", stretch=True, width=100, minwidth=80)
            elif col == "Open Ports":
                self.tree.column(col, anchor="center", stretch=True, width=130, minwidth=100)

        # Clear existing rows, then refresh data
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.refresh_treeview_data()

    def refresh_treeview_data(self):
        for device in self.current_devices:
            row_data = self.build_row_data(device)
            self.tree.insert("", tk.END, values=row_data)

    def build_row_data(self, device):
        row = [device.get("ip", "Unknown"), device.get("mac", "Unknown")]
        if self.show_vendor_var.get():
            row.append(device.get("vendor", "Not Fetched"))
        row.append(device.get("device_name", "Unknown"))
        if self.show_os_var.get():
            row.append(device.get("os_guess", "Unknown"))
        if self.show_port_var.get():
            ports = device.get("open_ports", [])
            row.append(",".join(map(str, ports)) if ports else "None")
        return tuple(row)

    # ----------------------- Scanning -----------------------
    def run_scan(self):
        self.update_status("Starting network scan...")
        self.scan_button.config(state="disabled")
        # Clear current devices and Treeview rows
        self.current_devices.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        threading.Thread(target=self.thread_scan, daemon=True).start()

    def thread_scan(self):
        try:
            # Step 1: Check NPCAP installation.
            check_npcap()

            # Step 2: Load MAC prefixes. ``load_mac_prefixes`` automatically
            # locates the bundled data directory when packaged.
            self.mac_prefixes = load_mac_prefixes()

            # Step 3: Get IP range.
            ip_range = get_ip_range()
            self.network = ip_range

            # Step 4: Scan the network asynchronously.
            devices = asyncio.run(scan_network(ip_range, self.mac_prefixes))

            # Initialize vendor and port info.
            for device in devices:
                device["vendor"] = "Not Fetched"
                device["open_ports"] = []
                device["os_guess"] = "Unknown"

            # Step 5: Get vendor info if enabled.
            if self.show_vendor_var.get():
                for device in devices:
                    device["vendor"] = get_mac_vendor(device.get("mac", ""), self.mac_prefixes)

            # Step 6: Get OS guess if enabled using advanced fingerprinting.
            if self.show_os_var.get():
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_device = {
                        executor.submit(fingerprint_os, device["ip"]): device for device in devices
                    }
                    for future in as_completed(future_to_device):
                        dev = future_to_device[future]
                        try:
                            dev["os_guess"] = future.result()
                        except Exception:
                            dev["os_guess"] = "Unknown"
            # Step 7: Scan open ports if enabled.
            if self.show_port_var.get():
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_device = {
                        executor.submit(probe_open_ports, device["ip"]): device for device in devices
                    }
                    for future in as_completed(future_to_device):
                        dev = future_to_device[future]
                        try:
                            dev["open_ports"] = future.result()
                        except Exception:
                            dev["open_ports"] = []
            self.current_devices = devices
            self.master.after(0, self.post_scan_update)
        except Exception as e:
            logger.error(f"An error occurred during scanning: {e}")
            self.master.after(0, lambda: self.scan_button.config(state="normal"))
            self.master.after(0, lambda: self.update_status("Ready"))

    def post_scan_update(self):
        self.refresh_treeview_data()
        self.scan_button.config(state="normal")
        if not self.current_devices:
            messagebox.showinfo("Scan Complete", "No devices found on the network.")
        else:
            messagebox.showinfo("Scan Complete", f"Found {len(self.current_devices)} device(s).")

    # ----------------------- Blocking -----------------------
    def update_block_parameters(self, *args):
        """Update the visibility of additional parameters based on selected method"""
        method = self.block_method_var.get()
        
        # Hide all parameters first
        self.tcp_port_label.grid_remove()
        self.tcp_port_entry.grid_remove()
        self.dns_server_label.grid_remove()
        self.dns_server_entry.grid_remove()
        
        # Show relevant parameters
        if method == "TCP SYN Flood":
            self.tcp_port_label.grid(row=0, column=0, padx=(5, 2), pady=5)
            self.tcp_port_entry.grid(row=0, column=1, padx=(2, 5), pady=5)
        elif method == "DNS Amplification":
            self.dns_server_label.grid(row=0, column=0, padx=(5, 2), pady=5)
            self.dns_server_entry.grid(row=0, column=1, padx=(2, 5), pady=5)

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

        method = self.block_method_var.get()
        if method in ["ARP Tornado", "MAC Flooding", "ICMP Unreachable", "TCP SYN Flood", "DNS Amplification"]:
            warning = (
                f"Warning: {method} is experimental and may disrupt "
                "network communications. Continue?"
            )
            if not messagebox.askyesno("Warning", warning):
                return

        # Additional validation for TCP SYN Flood
        if method == "TCP SYN Flood":
            try:
                port = int(self.tcp_port_var.get())
                if not (0 < port <= 65535):
                    raise ValueError
            except ValueError:
                messagebox.showwarning("Input Error", "Enter a valid port number (1-65535).")
                return

        # Additional validation for DNS Amplification
        if method == "DNS Amplification":
            dns_server = self.dns_server_var.get()
            if not dns_server:
                messagebox.showwarning("Input Error", "Enter a valid DNS server IP address.")
                return

        confirm = messagebox.askyesno(
            "Confirm Block",
            f"Block {target_ip} using {method} for {block_duration} seconds?"
        )
        if not confirm:
            return

        self.block_button.config(state="disabled")
        threading.Thread(
            target=self.thread_block,
            args=(target_ip, method, block_duration),
            daemon=True
        ).start()

    def thread_block(self, target_ip, block_method, block_duration):
        # Define a callback for logging that safely updates the status bar.
        def log_callback(message):
            self.master.after(0, lambda: self.update_status(message))
        
        if block_method == "ARP Poisoning":
            block_via_arp_poison(target_ip, self.network, block_duration=block_duration, log_callback=log_callback)
        elif block_method == "ARP Flooding":
            block_via_arp_flood(target_ip, self.network, block_duration=block_duration, log_callback=log_callback)
        elif block_method == "ARP Tornado":
            block_via_arp_tornado(target_ip, self.network, block_duration=block_duration, log_callback=log_callback)
        elif block_method == "MAC Flooding":
            block_via_mac_flood(target_ip, self.network, block_duration=block_duration, log_callback=log_callback)
        elif block_method == "ICMP Unreachable":
            block_via_icmp_unreachable(target_ip, self.network, block_duration=block_duration, log_callback=log_callback)
        elif block_method == "TCP SYN Flood":
            port = int(self.tcp_port_var.get())
            block_via_tcp_syn_flood(target_ip, port, block_duration=block_duration, log_callback=log_callback)
        elif block_method == "DNS Amplification":
            dns_server = self.dns_server_var.get()
            block_via_dns_amplification(target_ip, dns_server, block_duration=block_duration, log_callback=log_callback)

        self.master.after(0, lambda: self.block_finished(target_ip))

    def block_finished(self, target_ip):
        self.update_status("Blocking completed.")
        self.block_button.config(state="normal")
        messagebox.showinfo("Block Finished", f"Blocking of {target_ip} is finished.")

    # ----------------------- Save Results -----------------------
    def save_results(self):
        result = save_scan_results(self.current_devices, self.master)
        if result:
            self.update_status("Results saved successfully.")
        else:
            self.update_status("Save failed or cancelled.")

    def view_saved_results(self):
        FileViewer.open_file(self.master)

    # ----------------------- Status Updates -----------------------
    def update_status(self, message):
        self.status_bar.config(text=message)

def main():
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
