from scapy.all import *


# Victim's IP (Windows machine)
VICTIM_IP = "192.168.1.2"

# Spoofed source IP (can be modified)
ATTACKER_IP = "192.168.1.200"

INTERFACE = "\\Device\\NPF_{0B5347F4-28B6-47E3-9652-8173F5B57B74}"


def send_ssh_brute_force():
    """Trigger Rule: Possible SSH Brute Force Attack (Port 3000)"""
    print("[*] Sending SSH brute-force attempt...")
    for _ in range(5):  # Simulate multiple login attempts
        pkt = IP(src=ATTACKER_IP, dst=VICTIM_IP)/TCP(sport=RandShort(), dport=3000, flags="S")
        send(pkt, iface=INTERFACE)


send_ssh_brute_force()
