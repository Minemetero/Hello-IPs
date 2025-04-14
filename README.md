# Hello-IPs

## Overview

**Hello-IPs** is a modular network scanning and device blocking tool designed for local area networks (LANs). The tool concurrently discovers devices via ARP scanning and gathers rich information about each device including its IP address, MAC address, vendor (via OUI mapping), device name (from reverse DNS and nbtstat), and an optional list of open ports. Additionally, Hello-IPs offers multiple experimental methods to block unauthorized devices.

> [!WARNING]
> This software is intended for use **only on networks you administrate**.  
> The blocking methods provided are experimental and may disrupt network communications.  
> Use this tool at your own risk; the author disclaims all liability for misuse.

## Features

- **Concurrent Scanning:**  
  Scans each /24 subnet concurrently to speed up device discovery.
  
- **Rich Device Information:**  
  Retrieves IP, MAC, vendor, device name, and optionally probes common open ports (e.g., 22, 23, 80, 443, 3389).

- **Multiple Blocking Options:**  
  Choose from seven methods:
  - ARP Poisoning
  - ARP Flooding
  - ARP Tornado (experimental)
  - MAC Flooding (experimental)
  - ICMP Unreachable (experimental)
  - TCP SYN Flood (experimental)
  - DNS Amplification (experimental)

- **User-Friendly GUI:**  
  Built with Tkinter, the interface features a clear control layout.

## Project Structure

```
project_root/
 ├── data/
 │    └── nmap-mac-prefixes.txt   # Vendor mapping file
 ├── output/                      # Folder for generated output (e.g., ipconfig output)
 ├── network_scanner/
 │    ├── __init__.py
 │    ├── scanner.py              # Network scanning & utility functions
 │    ├── block.py                # Device blocking functions
 │    ├── probe.py                # Optional probing functions
 │    ├── gui.py                  # GUI for scanning and blocking
 │    └── utils/                  # Utility modules
 │         ├── __init__.py
 │         ├── logger.py          # Common logging system
 │         ├── log_saver.py       # Saving logs
 │         ├── file_saver.py      # Save scan results
 │         └── file_viewer.py     # View the file results
 ├── main.py                      # Application entry point
 └── requirements.txt             # Python dependencies
```

## Installation

### Windows & macOS Users
1. **Download the Executable:**
   - Go to the [Releases](https://github.com/Minemetero/Hello-IPs/releases) page
   - Download the latest `Hello-IPs.exe` file

2. **Run the Application:**
   - Windows, Mac: Double-click the downloaded `Hello-IPs.exe` file
   - If Windows SmartScreen appears, click "More info" and then "Run anyway"

### Linux Users
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Minemetero/Hello-IPs.git
   cd Hello-IPs
   ```

2. **Create and Activate a Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application:**
   ```bash
   python main.py
   ```

> [!TIP]
> **If you run into any issues during installation or usage, please open an issue on GitHub or contact the maintainers.**

## Usage

1. **Using the GUI:**
   - Click **"Scan Network"** to start scanning.
   - The table will display discovered devices along with IP, MAC, vendor, device name, and open ports.
   - To block a device, select it from the table, choose a blocking method from the dropdown (seven options available), and specify a duration.
   - Click **"Block Selected Device"** to initiate the blocking process.
   - If an experimental blocking method is selected, a warning prompt will appear before proceeding.

## License

This project is licensed under the [Apache License 2.0](LICENSE). All copyright remains with the author. The software is provided "AS IS" without warranties, and the user assumes full responsibility for any misuse or illegal activity arising from its use.

## Disclaimer

> [!WARNING]
> Hello-IPs is designed for authorized network management only. The blocking methods, particularly the experimental ones (ARP Tornado, MAC Flooding, and ICMP Unreachable), may severely disrupt network communications. Use them only on networks you administrate. The author disclaims all liability for any illegal or improper use of this software.

## Contributing

Contributions are welcome. Please fork the repository and submit a pull request with your enhancements or bug fixes.
