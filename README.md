# Hello-IPs

## Overview

**Hello-IPs** is a modular network scanning and device blocking tool designed for local area networks (LANs). The tool concurrently discovers devices via ARP scanning and gathers rich information about each device including its IP address, MAC address, vendor (via OUI mapping), device name (from reverse DNS and nbtstat), and an optional list of open ports. Additionally, Hello-IPs offers multiple experimental methods to block unauthorized devices.

**Important:**  
- This software is intended for use **only on networks you administrate**.  
- The blocking methods provided are experimental and may disrupt network communications.  
- Use this tool at your own risk; the author disclaims all liability for misuse.

## Features

- **Concurrent Scanning:**  
  Scans each /24 subnet concurrently to speed up device discovery.
  
- **Rich Device Information:**  
  Retrieves IP, MAC, vendor, device name, and optionally probes common open ports (e.g., 22, 23, 80, 443, 3389).

- **Multiple Blocking Options:**  
  Choose from five methods:
  - ARP Poisoning
  - ARP Flooding
  - ARP Tornado (experimental)
  - MAC Flooding (experimental)
  - ICMP Unreachable (experimental)

- **User-Friendly GUI:**  
  Built with Tkinter, the interface features a clear control layout.

## Project Structure

```
project_root/
 ├── data/
 │    └── nmap-mac-prefixes.txt   # Vendor mapping file
 ├── output/                      # Folder for generated output (e.g., ipconfig output)
 ├── network_scanner/
 │    ├── __init__.py             # (Empty package initializer)
 │    ├── scanner.py              # Network scanning & utility functions (using concurrent scanning)
 │    ├── block.py                # Device blocking functions (all methods)
 │    └── probe.py                # Optional probing functions (e.g., for open ports)
 │    └── gui.py                  # GUI for scanning and blocking
 ├── main.py                      # Application entry point
 └── requirements.txt             # Python dependencies (e.g., scapy>=2.4.5)
```

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Minemetero/Hello-IPs.git
   cd Hello-IPs
   ```

2. **(Optional) Create and Activate a Virtual Environment:**

   ```bash
   python -m venv venv
   # On macOS/Linux:
   source venv/bin/activate
   # On Windows:
   venv\Scripts\activate
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Vendor Mapping File:**

   Ensure that the `nmap-mac-prefixes.txt` file is located in the `data/` directory.

## Usage

1. **Run with Administrative Privileges:**  
   On Windows, run the application as an administrator (e.g., right-click your command prompt and select "Run as administrator") to allow raw packet operations.

2. **Start the Application:**

   ```bash
   python main.py
   ```

3. **Using the GUI:**
   - Click **"Scan Network"** to start scanning.
   - The table will display discovered devices along with IP, MAC, vendor, device name, and open ports.
   - To block a device, select it from the table, choose a blocking method from the dropdown (five options available), and specify a duration.
   - Click **"Block Selected Device"** to initiate the blocking process.
   - If an experimental blocking method is selected, a warning prompt will appear before proceeding.

## License

This project is licensed under the [Apache License 2.0](LICENSE). All copyright remains with the author. The software is provided "AS IS" without warranties, and the user assumes full responsibility for any misuse or illegal activity arising from its use.

## Disclaimer

**Warning:**  
Hello-IPs is designed for authorized network management only. The blocking methods, particularly the experimental ones (ARP Tornado, MAC Flooding, and ICMP Unreachable), may severely disrupt network communications. Use them only on networks you administrate. The author disclaims all liability for any illegal or improper use of this software.

## Contributing

Contributions are welcome. Please fork the repository and submit a pull request with your enhancements or bug fixes.
