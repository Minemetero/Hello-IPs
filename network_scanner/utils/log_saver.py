import os
import shutil
import tkinter as tk
from tkinter import messagebox, filedialog
from ..scanner import logger

def export_logs(parent_window=None):
    """
    Export the current log file to a user-selected location.
    
    Args:
        parent_window: Optional parent window for the file dialog
        
    Returns:
        bool: True if export was successful, False otherwise
    """
    try:
        # Export the same log file that CommonLogger writes to.
        # CommonLogger._log_file defaults to "hello-ips.log", so we use
        # that constant here to avoid mismatches.
        log_file = "hello-ips.log"
        if not os.path.exists(log_file):
            if parent_window:
                messagebox.showwarning("No Logs", "No log file found to export.")
            return False

        # Ask user for save location
        file_path = filedialog.asksaveasfilename(
            parent=parent_window,
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="hello-ips.log"
        )

        if file_path:  # User didn't cancel
            # Copy the log file to the new location
            shutil.copy2(log_file, file_path)
            logger.info(f"Logs exported to: {file_path}")
            if parent_window:
                messagebox.showinfo("Export Successful", f"Logs exported to:\n{file_path}")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to export logs: {e}")
        if parent_window:
            messagebox.showerror("Export Failed", f"Failed to export logs:\n{e}")
        return False 
