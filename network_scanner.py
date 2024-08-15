from scapy.all import ARP, Ether, srp, conf
import socket
import ipaddress
import os
import platform
import time

conf.verb = 0  # 关闭Scapy输出日志，提升性能

# 读取nmap-mac-prefixes.txt文件并创建MAC前缀到厂商的映射
def load_mac_prefixes(file_path):
    mac_prefixes = {}
    print("Loading MAC prefixes...")
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip():  # 忽略空行
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    prefix, vendor = parts
                    mac_prefixes[prefix.upper()] = vendor
    print("MAC prefixes loaded successfully!")
    return mac_prefixes

# 获取厂商信息
def get_mac_vendor(mac_address, mac_prefixes):
    mac_prefix = mac_address.upper()[:8]  # 提取前8个字符作为前缀
    return mac_prefixes.get(mac_prefix, "Unknown")

def get_ip_range():
    print("Determining IP range...")
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    subnet_mask = get_subnet_mask(local_ip)
    network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
    print(f"IP range determined: {network}")
    return network

def get_subnet_mask(ip):
    if platform.system().lower() == "windows":
        os.system("ipconfig > ipconfig_output.txt")
        with open("ipconfig_output.txt", "r") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if ip in line:
                    for j in range(i, i + 10):
                        if "Subnet Mask" in lines[j]:
                            return lines[j].split(":")[-1].strip()
        os.remove("ipconfig_output.txt")
    return "255.255.255.0"  # 默认子网掩码

def scan_network(ip_range, mac_prefixes):
    print(f"Starting network scan in range: {ip_range}...")
    
    devices = []
    for subnet in ip_range.subnets(new_prefix=24):
        print(f"Scanning subnet: {subnet}")
        arp_request = ARP(pdst=str(subnet))
        ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = ether_broadcast / arp_request

        answered_list = srp(arp_request_broadcast, timeout=3, retry=2, verbose=False)[0]

        for element in answered_list:
            device = {}
            device['ip'] = element[1].psrc
            device['mac'] = element[1].hwsrc
            device['vendor'] = get_mac_vendor(device['mac'], mac_prefixes)
            try:
                device['hostname'] = socket.gethostbyaddr(device['ip'])[0]
            except socket.herror:
                device['hostname'] = "Unknown"

            devices.append(device)

    print("Network scan completed!")
    return devices

if __name__ == "__main__":
    print("Initializing network scanner...")
    mac_prefixes = load_mac_prefixes('nmap-mac-prefixes.txt')  # 加载MAC前缀数据
    ip_range = get_ip_range()  # 自动获取合适的IP范围
    devices = scan_network(ip_range, mac_prefixes)

    print("Results:")
    print(f"{'IP Address':<15}{'MAC Address':<20}{'Vendor':<30}{'Hostname'}")
    print("-" * 80)
    for device in devices:
        ip = device['ip'] if device['ip'] else "Unknown"
        mac = device['mac'] if device['mac'] else "Unknown"
        vendor = device['vendor'] if device['vendor'] else "Unknown"
        hostname = device['hostname'] if device['hostname'] else "Unknown"

        print(f"{ip:<15}{mac:<20}{vendor:<30}{hostname}")
