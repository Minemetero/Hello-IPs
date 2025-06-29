import os
import json
import csv
from datetime import datetime
from tkinter import filedialog, messagebox

def save_scan_results(devices, parent_window=None):
    """
    Save network scan results to a file in either JSON or CSV format.
    
    Args:
        devices (list): List of device dictionaries containing scan results
        parent_window (tk.Tk, optional): Parent window for dialogs
        
    Returns:
        bool: True if save was successful, False otherwise
    """
    if not devices:
        if parent_window:
            messagebox.showwarning("Save Error", "No scan results to save. Please scan the network first.")
        return False
        
    # Create output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    
    # Ask user for file format
    if parent_window:
        file_format = messagebox.askquestion("Save Format", "Save as JSON? (Yes) or CSV? (No)")
    else:
        # Default to JSON if no parent window
        file_format = "yes"
    
    # Generate default filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"network_scan_{timestamp}"
    
    if file_format == "yes":
        # Save as JSON
        if parent_window:
            file_path = filedialog.asksaveasfilename(
                initialdir="output",
                initialfile=f"{default_filename}.json",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
        else:
            # Default path if no parent window
            file_path = os.path.join("output", f"{default_filename}.json")
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(devices, f, indent=4)
                if parent_window:
                    messagebox.showinfo("Save Successful", f"Results saved to {file_path}")
                return True
            except Exception as e:
                if parent_window:
                    messagebox.showerror("Save Error", f"Failed to save results: {str(e)}")
                return False
    else:
        # Save as CSV
        if parent_window:
            file_path = filedialog.asksaveasfilename(
                initialdir="output",
                initialfile=f"{default_filename}.csv",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
        else:
            # Default path if no parent window
            file_path = os.path.join("output", f"{default_filename}.csv")
        
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(["IP Address", "MAC Address", "Vendor", "Device Name", "Open Ports"])
                    # Write data
                    for device in devices:
                        ports = ",".join(map(str, device.get("open_ports", []))) if device.get("open_ports") else "None"
                        writer.writerow([
                            device.get("ip", "Unknown"),
                            device.get("mac", "Unknown"),
                            device.get("vendor", "Unknown"),
                            device.get("device_name", "Unknown"),
                            ports
                        ])
                if parent_window:
                    messagebox.showinfo("Save Successful", f"Results saved to {file_path}")
                return True
            except Exception as e:
                if parent_window:
                    messagebox.showerror("Save Error", f"Failed to save results: {str(e)}")
                return False
    
    return False 
