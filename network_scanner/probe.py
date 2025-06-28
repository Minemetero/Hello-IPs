import socket
from scapy.all import IP, ICMP, sr1


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
