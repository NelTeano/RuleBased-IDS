import pyshark
import re
from collections import defaultdict
import time

# Track SYN packets for Port Scan detection
syn_tracker = defaultdict(lambda: {"count": 0, "timestamp": time.time()})

# Track UDP packets for UDP Flood detection
udp_tracker = defaultdict(lambda: {"count": 0, "timestamp": time.time()})

# Load rules from file
def load_rules(rule_file):
    rules = []
    with open(rule_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                rules.append(line)
    return rules

# Function to check if a packet matches any rule
def match_rule(packet, rules):
    global syn_tracker, udp_tracker
    try:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = packet.transport_layer if hasattr(packet, 'transport_layer') and packet.transport_layer else "UNKNOWN"
            payload = packet.get_raw_packet()  # Get raw packet data

            # Check each rule
            for rule in rules:
                rule_parts = rule.split()
                if len(rule_parts) < 4:
                    continue
                rule_src, rule_dst, rule_proto, rule_payload = rule_parts

                if (rule_src == '*' or rule_src == src_ip) and \
                   (rule_dst == '*' or rule_dst == dst_ip) and \
                   (rule_proto == '*' or rule_proto.lower() == proto.lower()) and \
                   (re.search(rule_payload, str(payload)) if rule_payload != '*' else True):
                    print(f"[ALERT] Rule matched! Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}")

            # Detect SYN Scan
            if proto == "TCP" and hasattr(packet, 'tcp') and hasattr(packet.tcp, "flags"):
                flags = int(packet.tcp.flags, 16)  # Convert to integer
                if flags == 2:  # SYN flag only
                    syn_tracker[src_ip]["count"] += 1
                    now = time.time()
                    if now - syn_tracker[src_ip]["timestamp"] < 3:  # 3 sec window
                        if syn_tracker[src_ip]["count"] > 5:  # More than 5 SYNs in 3 sec
                            print(f"[ALERT] SYN Scan detected! Source: {src_ip}")
                    else:
                        syn_tracker[src_ip] = {"count": 1, "timestamp": now}

            # Detect UDP Flood
            if proto == "UDP":
                dst_port = int(packet.udp.dstport) if hasattr(packet, 'udp') else None

                # List of ports to ignore (common benign UDP traffic)
                ignored_ports = [53, 443]  # DNS and QUIC
                list_ips = ["142.251."]  # Google's IP block (partial match) list of ips that blocking the alert

                # Get source IP and check if it should be ignored
                if dst_port not in ignored_ports and not any(src_ip.startswith(ip) for ip in list_ips):
                    udp_tracker[src_ip]["count"] += 1
                    now = time.time()

                    if now - udp_tracker[src_ip]["timestamp"] < 5:  # 5 sec window
                        if udp_tracker[src_ip]["count"] > 50:  # Adjusted threshold
                            print(f"[ALERT] UDP Flood detected! Source: {src_ip}")
                    else:
                        udp_tracker[src_ip] = {"count": 1, "timestamp": now}


    except Exception as e:
        print(f"Error processing packet: {e}")

# Start live packet capture
def start_ids(interface, rule_file):
    rules = load_rules(rule_file)
    print(f"[INFO] IDS started on {interface}, monitoring packets...")

    capture = pyshark.LiveCapture(
        interface=interface,
        use_json=True,
        include_raw=True
    )

    for packet in capture:
        match_rule(packet, rules)


if __name__ == "__main__":
    INTERFACE = "\\Device\\NPF_{0B5347F4-28B6-47E3-9652-8173F5B57B74}"  # Change to your network interface
    RULE_FILE = "BasicRule.txt"
    start_ids(INTERFACE, RULE_FILE)
