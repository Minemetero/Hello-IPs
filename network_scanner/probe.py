import socket
from scapy.all import IP, ICMP, TCP, sr1


def guess_os(ip, timeout=1):
    """Return a simple OS guess based on the target's TTL value."""
    try:
        pkt = IP(dst=ip) / ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp:
            ttl = int(resp.ttl)
            if ttl <= 64:
                return "Linux/Unix"
            if ttl <= 128:
                return "Windows"
            if ttl <= 254:
                return "Solaris/AIX"
    except Exception:
        pass
    return "Unknown"


def fingerprint_os(ip, timeout=1):
    """Attempt to fingerprint the OS using TTL, TCP options, and service banners."""
    os_guess = guess_os(ip, timeout=timeout)

    # Try a TCP SYN to gather TTL and option information
    try:
        syn_pkt = IP(dst=ip) / TCP(dport=80, flags="S")
        resp = sr1(syn_pkt, timeout=timeout, verbose=False)
        if resp and resp.haslayer(TCP):
            ttl = int(resp.ttl)
            if ttl <= 64:
                os_guess = "Linux/Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            elif ttl <= 254:
                os_guess = "Solaris/AIX"

            opts = {opt[0] for opt in resp[TCP].options}
            if "SAckOK" in opts and os_guess == "Unknown":
                os_guess = "Linux/Unix"
            if "WScale" in opts and os_guess == "Unknown":
                os_guess = "Windows"
    except Exception:
        pass

    # Grab banners from common ports
    for port in (22, 80, 23):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = b""
                if port == 22:
                    banner = sock.recv(100)
                elif port == 80:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(100)
                else:
                    banner = sock.recv(100)

                banner_text = banner.decode(errors="ignore").lower()
                if any(x in banner_text for x in ["windows", "microsoft", "iis"]):
                    return "Windows"
                if any(x in banner_text for x in ["linux", "unix", "ubuntu", "debian", "nginx", "apache"]):
                    return "Linux/Unix"
                if "cisco" in banner_text:
                    return "Cisco IOS"
        except Exception:
            continue

    return os_guess

def probe_open_ports(ip, ports=[22, 23, 80, 443, 3389], timeout=0.5):
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((ip, port), timeout)
            sock.close()
            open_ports.append(port)
        except Exception:
            continue
    return open_ports
