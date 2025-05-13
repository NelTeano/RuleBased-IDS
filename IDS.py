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
    try:
        with open(rule_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    rules.append(line)
    except Exception as e:
        print(f"Error loading {rule_file}: {e}")
    return rules

# Function to check if a packet matches any rule from either format
def match_rule(packet, rules):
    global syn_tracker, udp_tracker
    try:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = packet.transport_layer if hasattr(packet, 'transport_layer') and packet.transport_layer else "UNKNOWN"
            payload = packet.get_raw_packet()  # Raw packet data

            # Loop through each rule and try to match
            for rule in rules:
                # --- Snort-style rules ---
                if rule.startswith("alert"):
                    parts = rule.split(None, 7)
                    if len(parts) < 8:
                        continue
                    # Expected format:
                    # alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (options)
                    _, rule_proto, rule_src, rule_src_port, arrow, rule_dst, rule_dst_port, options = parts

                    # Check protocol (case-insensitive)
                    if rule_proto.lower() != proto.lower():
                        continue

                    # Check source IP if rule is not "any"
                    if rule_src.lower() != "any" and rule_src != src_ip:
                        continue

                    # Check destination IP if rule is not "any"
                    if rule_dst.lower() != "any" and rule_dst != dst_ip:
                        continue

                    # Get packet destination port for TCP or UDP
                    packet_dst_port = None
                    if proto.lower() == "tcp" and hasattr(packet, 'tcp'):
                        packet_dst_port = packet.tcp.dstport
                    elif proto.lower() == "udp" and hasattr(packet, 'udp'):
                        packet_dst_port = packet.udp.dstport

                    # Check destination port if rule is not "any"
                    if rule_dst_port.lower() != "any" and packet_dst_port != rule_dst_port:
                        continue

                    # If the rule includes a flags specification (e.g., flags: S;), check it
                    flags_search = re.search(r'flags:\s*([^;]+);', options)
                    if flags_search:
                        expected_flags = flags_search.group(1).strip()
                        flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04,
                                    'P': 0x08, 'A': 0x10, 'U': 0x20,
                                    'E': 0x40, 'C': 0x80}
                        expected_mask = 0
                        for ch in expected_flags:
                            if ch in flag_map:
                                expected_mask |= flag_map[ch]
                        if not hasattr(packet, 'tcp'):
                            continue
                        actual_mask = int(packet.tcp.flags, 16)
                        if actual_mask != expected_mask:
                            continue

                    # Extract the message from options using an updated regex that allows whitespace
                    msg_search = re.search(r'msg:\s*"(.*?)";', options)
                    msg = msg_search.group(1) if msg_search else "Alert triggered"

                    # Print the alert message from the rule
                    print(f"[ALERT] {msg} Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}")

                # --- Basic rules (from BasicRule.txt) ---
                else:
                    rule_parts = rule.split()
                    if len(rule_parts) < 4:
                        continue
                    rule_src, rule_dst, rule_proto, rule_payload = rule_parts[:4]
                    if (rule_src != '*' and rule_src != src_ip):
                        continue
                    if (rule_dst != '*' and rule_dst != dst_ip):
                        continue
                    if (rule_proto != '*' and rule_proto.lower() != proto.lower()):
                        continue
                    if rule_payload != '*' and not re.search(rule_payload, str(payload)):
                        continue
                    print(f"[ALERT] Rule matched! Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}")

            # --- Additional Detection Logic ---
            # Detect SYN Scan (for TCP SYN packets)
            if proto == "TCP" and hasattr(packet, 'tcp') and hasattr(packet.tcp, "flags"):
                try:
                    flags_int = int(packet.tcp.flags, 16)
                except Exception:
                    flags_int = 0
                if flags_int == 2:  # SYN flag only (0x02)
                    syn_tracker[src_ip]["count"] += 1
                    now = time.time()
                    if now - syn_tracker[src_ip]["timestamp"] < 3:  # 3-second window
                        if syn_tracker[src_ip]["count"] > 5:
                            print(f"[ALERT] SYN Scan detected! Source: {src_ip}")
                    else:
                        syn_tracker[src_ip] = {"count": 1, "timestamp": now}

            # Detect UDP Flood
            if proto == "UDP":
                dst_port = int(packet.udp.dstport) if hasattr(packet, 'udp') else None
                ignored_ports = [53, 443]  # Common benign UDP traffic ports
                list_ips = ["142.251.220.196", "142.251.220.206"]  # Example: ignore certain IP blocks (e.g., Google)
                if dst_port not in ignored_ports and not any(src_ip.startswith(ip) for ip in list_ips):
                    udp_tracker[src_ip]["count"] += 1
                    now = time.time()
                    if now - udp_tracker[src_ip]["timestamp"] < 5:  # 5-second window
                        if udp_tracker[src_ip]["count"] > 50:
                            print(f"[ALERT] UDP Flood detected! Source: {src_ip}")
                    else:
                        udp_tracker[src_ip] = {"count": 1, "timestamp": now}

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start live packet capture using multiple rule files
def start_ids(interface, rule_files):
    combined_rules = []
    for rule_file in rule_files:
        combined_rules.extend(load_rules(rule_file))
    print(f"[INFO] IDS started on {interface}, monitoring packets with {len(combined_rules)} rules...")
    
    capture = pyshark.LiveCapture(
        interface=interface,
        use_json=True,
        include_raw=True
    )
    
    for packet in capture:
        match_rule(packet, combined_rules)

if __name__ == "__main__":
    INTERFACE = "\\Device\\NPF_{0B5347F4-28B6-47E3-9652-8173F5B57B74}"  # Change to your network interface
    # List both rule files: one with Snort-style rules and one with basic rules
    RULE_FILES = ["rules.rules", "BasicRule.txt"]
    start_ids(INTERFACE, RULE_FILES)
