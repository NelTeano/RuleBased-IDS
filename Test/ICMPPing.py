from scapy.all import *

target_ip = "192.168.1.2"  # Replace with the target IP

print(f"Sending ICMP Ping to {target_ip}")

for _ in range(5):  # Sends 5 ICMP Echo Requests
    packet = IP(dst=target_ip) / ICMP()
    send(packet, verbose=False)

print("ICMP Ping attack sent!")
