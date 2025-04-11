import socket
import ipaddress
import subprocess
import os
import platform
import urllib.request
import subprocess
import tkinter as tk
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp, conf, L3socket

conf.verb = 0

def install_npcap():
    if platform.system().lower() != "windows":
        messagebox.showerror("Installation Error",
                             "NPCAP installation is only supported on Windows.")
        return

    # URL for the npcap installer; update version if needed.
    npcap_url = "https://npcap.com/dist/npcap-1.81.exe"
    # Download installer to the TEMP directory, or fallback to current working directory.
    temp_dir = os.getenv("TEMP") or os.getcwd()
    installer_path = os.path.join(temp_dir, "npcap-1.81.exe")

    try:
        messagebox.showinfo("Downloading NPCAP",
                            "Downloading the NPCAP installer. This may take a moment...")
        with urllib.request.urlopen(npcap_url) as response:
            with open(installer_path, "wb") as out_file:
                out_file.write(response.read())
    except Exception as e:
        messagebox.showerror("Download Error",
                             f"Failed to download the NPCAP installer:\n{e}")
        return

    try:
        # Run the installer using the silent flag /S if supported by the installer.
        # You might need to adjust the flags depending on the NPCAP version.
        subprocess.run([installer_path, "/S"], check=True)
        messagebox.showinfo("Installation Complete",
                            "NPCAP has been installed successfully. Please restart the program for changes to take effect.")
    except Exception as e:
        messagebox.showerror("Installation Error",
                             f"Failed to run the NPCAP installer:\n{e}")

def check_npcap():
    try:
        test_socket = conf.L2socket()
        test_socket.close()
    except Exception:
        # Ensure there is a Tkinter root window; if not, create a temporary one.
        root = tk._default_root
        if not root:
            root = tk.Tk()
            root.withdraw()  # Hide the main window

        answer = messagebox.askyesno("NPCAP Missing",
                                     "NPCAP is not installed. Would you like to install NPCAP for improved performance?")
        if answer:
            install_npcap()
        else:
            messagebox.showwarning("NPCAP Warning",
                                   "No NPCAP installed; using Layer 3 socket instead.")
        # Fallback to using the Layer 3 socket
        conf.L2socket = L3socket

def load_mac_prefixes(file_path):
    mac_prefixes = {}
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        prefix, vendor = parts
                        mac_prefixes[prefix.upper()] = vendor.strip()
    except Exception as e:
        print("Failed to load MAC prefixes:", e)
    return mac_prefixes

def get_mac_vendor(mac_address, mac_prefixes):
    clean_mac = mac_address.upper().replace(":", "").replace("-", "")
    return mac_prefixes.get(clean_mac[:6], "Unknown")

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        if platform.system().lower() == "windows":
            try:
                output = subprocess.check_output(f"nbtstat -A {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    if '<00>' in line and 'UNIQUE' in line:
                        parts = line.split()
                        if parts:
                            return parts[0]
            except Exception:
                pass
        return "Unknown"

def get_subnet_mask(ip):
    if platform.system().lower() == "windows":
        try:
            output = subprocess.check_output("ipconfig", shell=True, text=True)
            os.makedirs("output", exist_ok=True)
            with open(os.path.join("output", "ipconfig_output.txt"), "w") as f:
                f.write(output)
            lines = output.splitlines()
            for i, line in enumerate(lines):
                if ip in line:
                    for j in range(i, min(i + 10, len(lines))):
                        if "Subnet Mask" in lines[j]:
                            return lines[j].split(":")[-1].strip()
        except Exception as e:
            print("Error retrieving subnet mask:", e)
    return "255.255.255.0"

def get_ip_range():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    subnet_mask = get_subnet_mask(local_ip)
    return ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)

def scan_subnet(subnet, mac_prefixes):
    results = []
    arp_req = ARP(pdst=str(subnet))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req
    try:
        answered = srp(packet, timeout=3, retry=2, verbose=False)[0]
    except Exception as e:
        print("Error scanning", subnet, e)
        return results
    for element in answered:
        device = {
            'ip': element[1].psrc,
            'mac': element[1].hwsrc,
            'vendor': get_mac_vendor(element[1].hwsrc, mac_prefixes),
            'device_name': get_device_name(element[1].psrc)
        }
        results.append(device)
    return results

def scan_network(ip_range, mac_prefixes):
    devices = []
    subnets = list(ip_range.subnets(new_prefix=24))
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subnet = {executor.submit(scan_subnet, subnet, mac_prefixes): subnet for subnet in subnets}
        for future in as_completed(future_to_subnet):
            try:
                devices.extend(future.result())
            except Exception:
                pass
    return devices
