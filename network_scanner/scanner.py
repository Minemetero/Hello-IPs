import socket
import ipaddress
import subprocess
import os
import platform
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp, conf
from .utils.logger import CommonLogger

# Configure Scapy
conf.verb = 0
conf.timeout = 2

# Create logger instance
logger = CommonLogger('scanner')

def check_npcap():
    try:
        test_socket = conf.L2socket()
        test_socket.close()
        logger.info("NPCAP is available and working properly")
        return True
    except Exception as e:
        logger.warning(f"No npcap installed or not working properly: {e}")
        logger.info("Falling back to Layer 3 socket")
        conf.L2socket = conf.L3socket
        return False

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
        logger.info(f"Successfully loaded {len(mac_prefixes)} MAC prefixes")
    except Exception as e:
        logger.error(f"Failed to load MAC prefixes: {e}")
    return mac_prefixes

def get_mac_vendor(mac_address, mac_prefixes):
    clean_mac = mac_address.upper().replace(":", "").replace("-", "")
    return mac_prefixes.get(clean_mac[:6], "Unknown")

def get_device_name(ip, timeout=1):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        if platform.system().lower() == "windows":
            try:
                output = subprocess.check_output(
                    f"nbtstat -A {ip}", 
                    shell=True, 
                    text=True, 
                    stderr=subprocess.DEVNULL,
                    timeout=timeout
                )
                for line in output.splitlines():
                    if '<00>' in line and 'UNIQUE' in line:
                        parts = line.split()
                        if parts:
                            return parts[0]
            except Exception as e:
                logger.debug(f"Failed to get NetBIOS name for {ip}: {e}")
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
            logger.error(f"Error retrieving subnet mask: {e}")
    return "255.255.255.0"

def get_ip_range():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        subnet_mask = get_subnet_mask(local_ip)
        network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
        logger.info(f"Detected local network: {network}")
        return network
    except Exception as e:
        logger.error(f"Failed to determine local IP range: {e}")
        raise

def scan_subnet(subnet, mac_prefixes, timeout=3, retry=2):
    results = []
    
    if not check_npcap():
        logger.warning("NPCAP not available, scanning may be limited")
    
    arp_req = ARP(pdst=str(subnet))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req
    
    try:
        answered = srp(packet, timeout=timeout, retry=retry, verbose=False)[0]
        logger.info(f"Found {len(answered)} devices in subnet {subnet}")
    except Exception as e:
        logger.error(f"Error scanning subnet {subnet}: {e}")
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

def scan_network(ip_range, mac_prefixes, max_workers=10, subnet_prefix=24):
    devices = []
    try:
        subnets = list(ip_range.subnets(new_prefix=subnet_prefix))
        logger.info(f"Scanning {len(subnets)} subnets with {max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subnet = {
                executor.submit(scan_subnet, subnet, mac_prefixes): subnet 
                for subnet in subnets
            }
            
            for future in as_completed(future_to_subnet):
                try:
                    devices.extend(future.result())
                except Exception as e:
                    logger.error(f"Error processing subnet: {e}")
                    
        logger.info(f"Scan completed. Found {len(devices)} devices")
    except Exception as e:
        logger.error(f"Network scan failed: {e}")
        
    return devices
