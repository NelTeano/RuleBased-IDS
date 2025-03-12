# from scapy.all import *

# target_ip = "192.168.1.2"  # Replace with target IP
# port = 80  # HTTP port

# print("Sending malicious payload...")

# packet = IP(dst=target_ip)/TCP(dport=port)/Raw(load="malicious_payload")
# send(packet, verbose=False)

# print("Payload sent.")

from scapy.all import *

target_ip = "192.168.1.2"  # Change to your Windows machine's IP
target_port = 80  # Any open port (HTTP for example)

packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load="malicious_payload")
send(packet, verbose=False)

print("Test packet sent!")

