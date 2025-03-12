from scapy.all import *

target_ip = "192.168.1.2"  # Replace with target IP
ports = [22, 23, 80, 443, 8080]  # Common ports to scan

print(f"Starting SYN scan on {target_ip}...")

for port in ports:
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")  # SYN flag
    send(packet, verbose=False)

print("SYN scan completed.")
