import socket
import ipaddress
import subprocess
import os
import platform
import logging
import asyncio
from scapy.all import ARP, Ether, conf, AsyncSniffer, sendp
from .utils.logger import CommonLogger

# Configure Scapy
conf.verb = 0
conf.timeout = 2

# Create logger instance
logger = CommonLogger('scanner')

# Cache for NPCAP check result
_npcap_checked = False
_npcap_available = False

def check_npcap():
    global _npcap_checked, _npcap_available
    
    if not _npcap_checked:
        try:
            test_socket = conf.L2socket()
            test_socket.close()
            _npcap_available = True
            logger.info("NPCAP is available and working properly")
        except Exception as e:
            _npcap_available = False
            logger.warning(f"No npcap installed or not working properly: {e}")
            logger.info("Falling back to Layer 3 socket")
            conf.L2socket = conf.L3socket
        _npcap_checked = True
    
    return _npcap_available

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

async def scan_subnet(subnet, mac_prefixes, timeout=3, retry=2):
    """Asynchronously scan a subnet for active devices."""
    results = []

    if not check_npcap():
        logger.warning("NPCAP not available, scanning may be limited")

    arp_req = ARP(pdst=str(subnet))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req

    try:
        # Use AsyncSniffer without a timeout so we control when to stop it.
        sniffer = AsyncSniffer(filter="arp and arp[6:2] == 2")
        sniffer.start()
        await asyncio.to_thread(sendp, packet, verbose=False)
        await asyncio.sleep(timeout)
        # sniffer.stop() returns the captured packets.
        answered = sniffer.stop()
        logger.info(f"Found {len(answered)} devices in subnet {subnet}")
    except Exception as e:
        logger.error(f"Error scanning subnet {subnet}: {e}")
        return results

    for pkt in answered:
        if ARP in pkt and pkt[ARP].op == 2:
            device = {
                'ip': pkt[ARP].psrc,
                'mac': pkt[ARP].hwsrc,
                'vendor': get_mac_vendor(pkt[ARP].hwsrc, mac_prefixes),
                'device_name': get_device_name(pkt[ARP].psrc)
            }
            results.append(device)
    return results

async def scan_network(ip_range, mac_prefixes, max_workers=10, subnet_prefix=24):
    """Asynchronously scan a network by scanning subnets concurrently."""
    devices = []
    try:
        subnets = list(ip_range.subnets(new_prefix=subnet_prefix))
        logger.info(
            f"Scanning {len(subnets)} subnets with up to {max_workers} workers"
        )

        semaphore = asyncio.Semaphore(max_workers)

        async def worker(subnet):
            async with semaphore:
                return await scan_subnet(subnet, mac_prefixes)

        tasks = [asyncio.create_task(worker(subnet)) for subnet in subnets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error processing subnet: {result}")
            else:
                devices.extend(result)

        logger.info(f"Scan completed. Found {len(devices)} devices")
    except Exception as e:
        logger.error(f"Network scan failed: {e}")

    return devices
