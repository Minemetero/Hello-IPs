import socket

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
