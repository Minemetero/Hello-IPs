import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import csv

class FileViewer:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("File Viewer")
        self.window.geometry("900x600")
        self.window.configure(bg="white")
        self.window.resizable(True, True)

        # Create a frame for the content
        self.content_frame = ttk.Frame(self.window)
        self.content_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Create treeview with scrollbar
        self.tree = ttk.Treeview(self.content_frame, show="headings", selectmode="browse")
        self.tree.pack(expand=True, fill="both", side="left")

        scrollbar = ttk.Scrollbar(self.content_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Apply the same style as main window
        style = ttk.Style()
        style.theme_use("clam")

    def display_content(self, content, file_type):
        """Display content in the treeview with proper formatting"""
        if file_type == "json":
            try:
                # Parse JSON content if it's a string
                if isinstance(content, str):
                    data = json.loads(content)
                else:
                    data = content

                if not data:
                    return

                # Set up columns based on the first item
                if isinstance(data, list) and len(data) > 0:
                    # Get all possible columns from all items
                    columns = set()
                    for item in data:
                        columns.update(item.keys())
                    columns = sorted(list(columns))
                    
                    self.tree["columns"] = columns
                    for col in columns:
                        self.tree.heading(col, text=col)
                        self.tree.column(col, anchor="center", stretch=True, width=100)

                    # Insert data
                    for item in data:
                        values = [str(item.get(col, "")) for col in columns]
                        self.tree.insert("", tk.END, values=values)
                else:
                    # Single JSON object
                    columns = ["Key", "Value"]
                    self.tree["columns"] = columns
                    for col in columns:
                        self.tree.heading(col, text=col)
                        self.tree.column(col, anchor="center", stretch=True, width=200)
                    
                    for key, value in data.items():
                        self.tree.insert("", tk.END, values=(key, str(value)))
            except json.JSONDecodeError as e:
                messagebox.showerror("Error", f"Failed to parse JSON: {str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")

        elif file_type == "csv":
            try:
                # Parse CSV content
                lines = content.strip().split('\n')
                reader = csv.reader(lines)
                headers = next(reader)  # Get headers

                # Set up columns
                self.tree["columns"] = headers
                for col in headers:
                    self.tree.heading(col, text=col)
                    self.tree.column(col, anchor="center", stretch=True, width=100)

                # Insert data
                for row in reader:
                    self.tree.insert("", tk.END, values=row)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to parse CSV: {str(e)}")

    @staticmethod
    def open_file(parent):
        """Open a file dialog and display the selected file in a new viewer window."""
        file_path = filedialog.askopenfilename(
            initialdir="output",
            title="Select a file to view",
            filetypes=[
                ("All supported files", "*.json;*.csv"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return

        try:
            file_type = "json" if file_path.lower().endswith('.json') else "csv"
            
            with open(file_path, 'r') as f:
                content = f.read()

            viewer = FileViewer(parent)
            viewer.display_content(content, file_type)
            viewer.window.focus_force()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}") 
