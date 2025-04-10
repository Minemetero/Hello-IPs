import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from .scanner import check_npcap, load_mac_prefixes, get_ip_range, scan_network, get_mac_vendor
from .block import (block_via_arp_poison, block_via_arp_flood, block_via_arp_tornado,
                    block_via_mac_flood, block_via_icmp_unreachable)
from .probe import probe_open_ports
from .utils import save_scan_results, FileViewer

class NetworkScannerApp:
    def __init__(self, master):
        # Make the main window's background white
        self.master = master
        master.configure(bg="white")
        master.title("Hello-IPs: LAN Device Scanner")
        master.geometry("900x600")
        master.resizable(True, True)

        # -----------------------------------------
        # Use Style for Ttk components if desired
        style = ttk.Style()
        style.theme_use("clam")
        # -----------------------------------------

        # Track whether we show vendor / ports columns
        self.show_vendor_var = tk.BooleanVar(value=True)
        self.show_port_var = tk.BooleanVar(value=True)

        # Data storage
        self.network = None
        self.current_devices = []
        self.mac_prefixes = {}

        # Create menus (File, Options, Help)
        self.create_menu()

        # Header frame (tk, not ttk) to remove gray background
        self.header_frame = tk.Frame(master, bg="white")
        self.header_frame.pack(fill="x", padx=10, pady=10)

        # "Hello-IPs" title with white background
        self.header_label = tk.Label(self.header_frame, 
                                    text="Hello-IPs", 
                                    font=("Helvetica", 20, "bold"),
                                    bg="white")  # match frame bg
        self.header_label.pack(expand=True)
        self.header_label.configure(anchor="center", justify="center")

        # Top controls frame (tk, not ttk) so background is white
        self.top_control_frame = tk.Frame(master, bg="white")
        self.top_control_frame.pack(fill="x", padx=10, pady=5)
        self.create_top_controls(self.top_control_frame)

        # Main content frame (can be ttk or tk; here we use ttk but it's fine)
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(expand=True, fill="both", padx=10, pady=5)
        self.main_frame.columnconfigure(0, weight=3)
        self.main_frame.columnconfigure(1, weight=1)

        self.create_treeview(self.main_frame)
        self.create_blocking_panel(self.main_frame)

        # Status bar at the bottom
        self.status_bar = ttk.Label(master, text="Ready", relief="sunken", anchor="w")
        self.status_bar.pack(side="bottom", fill="x")

    def create_menu(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Scan Network", command=self.run_scan)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_command(label="Open File", command=self.view_saved_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Options menu: two checkbuttons to toggle Vendor and Open Ports columns.
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
        menubar.add_cascade(label="Options", menu=options_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Support", command=self.show_support)
        menubar.add_cascade(label="Help", menu=help_menu)

    def show_about(self):
        messagebox.showinfo("About", "Hello-IPs LAN Device Scanner\nDevloper: Minemetero")

    def show_support(self):
        import webbrowser
        webbrowser.open("https://github.com/Minemetero/Hello-IPs/issues")
        messagebox.showinfo("Support", "Opening GitHub Issues page.")

    def create_top_controls(self, parent):
        # Using ttk.Button for consistent styling with the block button
        self.scan_button = ttk.Button(parent, text="Scan", command=self.run_scan)
        self.scan_button.grid(row=0, column=0, padx=5, pady=5)

        self.save_button = ttk.Button(parent, text="Save Results", command=self.save_results)
        self.save_button.grid(row=0, column=1, padx=5, pady=5)

        parent.columnconfigure(2, weight=1)

    def create_treeview(self, parent):
        results_container = ttk.Frame(parent)
        results_container.grid(row=0, column=0, sticky="nsew")
        parent.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(results_container, show="headings", selectmode="browse")
        self.tree.pack(expand=True, fill="both", side="left")

        scrollbar = ttk.Scrollbar(results_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Initialize the columns based on the default checkbox settings.
        self.update_treeview_columns()

    def create_blocking_panel(self, parent):
        # Blocking panel placed in the right column of the main frame
        self.blocking_panel = ttk.Frame(parent, relief="groove", borderwidth=2)
        self.blocking_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        # Configure grid weights for centering
        self.blocking_panel.grid_columnconfigure(0, weight=1)
        self.blocking_panel.grid_columnconfigure(1, weight=1)

        # Row 0: "Blocking" heading - centered
        heading_frame = ttk.Frame(self.blocking_panel)
        heading_frame.grid(row=0, column=0, columnspan=2, pady=(10, 15))
        heading_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(heading_frame, text="Blocking", font=("Helvetica", 14, "bold")).grid(
            row=0, column=0
        )

        # Row 1: "Block Method" label & OptionMenu
        ttk.Label(self.blocking_panel, text="Block Method:").grid(
            row=1, column=0, sticky="e", padx=(5, 2), pady=5
        )
        self.block_method_var = tk.StringVar(value="ARP Poisoning")
        methods = ["ARP Poisoning", "ARP Flooding", "ARP Tornado", "MAC Flooding", "ICMP Unreachable"]
        self.method_menu = ttk.OptionMenu(self.blocking_panel, self.block_method_var, methods[0], *methods)
        self.method_menu.grid(row=1, column=1, sticky="w", padx=(2, 5), pady=5)

        # Row 2: "Duration (s):" with aligned entry
        ttk.Label(self.blocking_panel, text="Duration (s):").grid(
            row=2, column=0, sticky="e", padx=(5, 2), pady=5
        )
        self.duration_var = tk.StringVar(value="60")
        self.duration_entry = ttk.Entry(self.blocking_panel, textvariable=self.duration_var, width=10)
        self.duration_entry.grid(row=2, column=1, sticky="w", padx=(2, 5), pady=5)

        # Row 3: "Block Device" button - centered with proper spacing
        button_frame = ttk.Frame(self.blocking_panel)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(15, 10))
        button_frame.grid_columnconfigure(0, weight=1)
        
        self.block_button = ttk.Button(button_frame, text="Block Device", command=self.block_selected_device)
        self.block_button.grid(row=0, column=0)

    # ----------------------- Dynamic Treeview Columns -----------------------
    def update_treeview_columns(self):
        # Build the list of columns based on toggles
        columns = ["IP Address", "MAC Address"]
        if self.show_vendor_var.get():
            columns.append("Vendor")
        columns.append("Device Name")
        if self.show_port_var.get():
            columns.append("Open Ports")

        self.tree["columns"] = columns

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", stretch=True)

        # Clear existing rows and refresh the data
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
        if self.show_port_var.get():
            ports = device.get("open_ports", [])
            row.append(",".join(map(str, ports)) if ports else "None")
        return tuple(row)

    # ----------------------- Scanning and Data Fetching -----------------------
    def run_scan(self):
        self.update_status("Scanning network, this will take a while. Please wait patiently.")
        self.scan_button.config(state="disabled")
        # Clear out current devices and table
        self.current_devices.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        threading.Thread(target=self.thread_scan, daemon=True).start()

    def thread_scan(self):
        try:
            check_npcap()
            mac_prefix_path = os.path.join("data", "nmap-mac-prefixes.txt")
            self.mac_prefixes = load_mac_prefixes(mac_prefix_path)
            ip_range = get_ip_range()
            self.network = ip_range

            # First scan the network
            devices = scan_network(ip_range, self.mac_prefixes)
            # Initialize fields to default values
            for device in devices:
                device["vendor"] = "Not Fetched"
                device["open_ports"] = []
            # If vendor column is enabled, fetch vendor info
            if self.show_vendor_var.get():
                for device in devices:
                    device["vendor"] = get_mac_vendor(device.get("mac", ""), self.mac_prefixes)
            # If open ports column is enabled, probe open ports for all devices concurrently
            if self.show_port_var.get():
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_device = {executor.submit(probe_open_ports, device["ip"]): device for device in devices}
                    for future in as_completed(future_to_device):
                        dev = future_to_device[future]
                        try:
                            dev["open_ports"] = future.result()
                        except Exception:
                            dev["open_ports"] = []

            self.current_devices = devices
            self.master.after(0, self.post_scan_update)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {e}"))
            self.master.after(0, lambda: self.scan_button.config(state="normal"))
            self.update_status("Ready")

    def post_scan_update(self):
        self.refresh_treeview_data()
        self.update_status("Scan complete.")
        self.scan_button.config(state="normal")
        if not self.current_devices:
            messagebox.showinfo("Scan Complete", "No devices found on the network.")
        else:
            messagebox.showinfo("Scan Complete", f"Found {len(self.current_devices)} device(s).")

    # ----------------------- Blocking Functions -----------------------
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
        if self.block_method_var.get() in ["ARP Tornado", "MAC Flooding", "ICMP Unreachable"]:
            warning = (
                f"Warning: {self.block_method_var.get()} is experimental and may disrupt "
                "network communications. Continue?"
            )
            if not messagebox.askyesno("Warning", warning):
                return
        confirm = messagebox.askyesno(
            "Confirm Block",
            f"Block {target_ip} using {self.block_method_var.get()} for {block_duration} seconds?"
        )
        if not confirm:
            return
        self.block_button.config(state="disabled")
        self.update_status(f"Blocking {target_ip}...")
        threading.Thread(
            target=self.thread_block,
            args=(target_ip, self.block_method_var.get(), block_duration),
            daemon=True
        ).start()

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
