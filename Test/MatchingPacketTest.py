from scapy.all import *

target_ip = "192.168.1.2"  # Replace with target victim machine IP

# Define attack scenarios with corresponding ports and protocols
attack_scenarios = {
    "FTP Brute Force Attack": (21, "TCP"),
    "Telnet Brute Force Attack": (23, "TCP"),
    "SMTP Relay Attack": (25, "TCP"),
    "DNS Amplification Attack": (53, "UDP"),
    "SNMP Attack": (161, "UDP"),
    "MySQL Brute Force Attack": (3306, "TCP"),
    "RDP Brute Force Attack": (3389, "TCP"),
    "SMB Exploit Attempt": (445, "TCP"),
    "HTTP Flood Attack": (80, "UDP"),
    "HTTPS Flood Attack": (443, "UDP"),
    "UDP Chargen Reflection DDoS": (19, "UDP"),
    "NTP Amplification Attack": (123, "UDP"),
    "SSDP Amplification Attack": (1900, "UDP"),
    "mDNS Amplification Attack": (5353, "UDP"),
    "ICMP Flood Attack": (None, "ICMP"),
    "Slowloris HTTP DoS Attack": (80, "TCP"),
    "ARP Spoofing Attack": (None, "ARP"),
    "DNS Spoofing Attack": (None, "DNS"),
    "SSL Strip Attack": (443, "TCP"),
    "Proxy Interception": (8080, "TCP"),
}

def send_tcp_attack(port, attack_name):
    """Send a TCP SYN packet to simulate an attack."""
    print(f"Simulating {attack_name} on port {port} (TCP)...")
    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")  # SYN flag
    send(packet, verbose=False)

def send_udp_attack(port, attack_name):
    """Send a UDP packet to simulate an attack."""
    print(f"Simulating {attack_name} on port {port} (UDP)...")
    packet = IP(dst=target_ip) / UDP(dport=port) / Raw(load="MaliciousPayload")
    send(packet, verbose=False)

def send_icmp_attack(attack_name):
    """Send ICMP Echo Requests (Ping Flood)."""
    print(f"Simulating {attack_name} (ICMP Flood)...")
    packet = IP(dst=target_ip) / ICMP()
    send(packet, count=10, verbose=False)

def send_arp_spoofing(attack_name):
    """Send ARP spoofing packet."""
    print(f"Simulating {attack_name} (ARP Spoofing)...")
    packet = ARP(op=2, psrc="192.168.1.1", pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
    send(packet, verbose=False)

def send_dns_spoofing(attack_name):
    """Send a fake DNS response (simplified)."""
    print(f"Simulating {attack_name} (DNS Spoofing)...")
    packet = IP(dst=target_ip) / UDP(dport=53) / Raw(load="FakeDNSResponse")
    send(packet, verbose=False)

print("Starting attack simulations...\n")

# Process each attack scenario
for attack, (port, proto) in attack_scenarios.items():
    if proto == "TCP":
        send_tcp_attack(port, attack)
    elif proto == "UDP":
        send_udp_attack(port, attack)
    elif proto == "ICMP":
        send_icmp_attack(attack)
    elif proto == "ARP":
        send_arp_spoofing(attack)
    elif proto == "DNS":
        send_dns_spoofing(attack)

print("\nAttack simulations completed.")
