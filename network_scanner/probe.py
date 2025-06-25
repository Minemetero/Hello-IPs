import socket
import subprocess
import re

# Map scan method names to corresponding nmap flags
NMAP_SCAN_MODES = {
    "quick": ["-F"],
    "stealth": ["-sS"],
    "udp": ["-sU"],
    "intense": ["-sS", "-sU", "-T4"],
}

# User-facing labels for each scanning method
SCAN_METHOD_LABELS = {
    "socket": "Basic (Socket)",
    "quick": "Quick Nmap Scan",
    "stealth": "Stealth Nmap Scan",
    "udp": "UDP Nmap Scan",
    "intense": "Intense Nmap Scan",
}


def _run_nmap(ip, flags, ports=None):
    """Run nmap with the provided ``flags`` and return a list of open ports.

    Parameters
    ----------
    ip : str
        Target IP address.
    ports : list[int] | None
        Optional list of ports to scan.

    Returns
    -------
    list[int]
        List of open ports reported by nmap. Returns an empty list on error.
    """

    cmd = ["nmap", *flags, "-Pn"]
    if ports:
        port_str = ",".join(str(p) for p in ports)
        cmd.extend(["-p", port_str])
    cmd.append(ip)

    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []

    open_ports = []
    for line in output.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open", line)
        if match:
            try:
                open_ports.append(int(match.group(1)))
            except ValueError:
                continue
    return open_ports


def probe_open_ports(ip, ports=None, timeout=0.5, method="socket"):
    """Probe open ports using sockets or several ``nmap`` modes.

    Parameters
    ----------
    ip : str
        Target IP address.
    ports : list[int] | None
        Ports to scan. If ``None`` a small default set is used.
    timeout : float
        Timeout for socket connections.
    method : str
        Scan method name. ``"socket"`` performs a simple socket probe. Any other
        value must match a key in :data:`NMAP_SCAN_MODES` to run an ``nmap`` scan.

    Returns
    -------
    list[int]
        List of detected open ports.
    """

    if ports is None:
        ports = [22, 23, 80, 443, 3389]

    if method != "socket":
        flags = NMAP_SCAN_MODES.get(method)
        if flags is None:
            return []
        return _run_nmap(ip, flags, ports)

    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((ip, port), timeout)
            sock.close()
            open_ports.append(port)
        except Exception:
            continue
    return open_ports
