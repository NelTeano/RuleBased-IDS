import pyshark
import re
from collections import defaultdict
import time
import requests

# Constants
IDS_SERVER_PORT = 5000  # Flask server port for intrusion detection
print(f"[INFO] IDS_SERVER_PORT: {IDS_SERVER_PORT}")

# Track HTTP POST requests
last_post_request = 0 # Last time a POST request was sent (Do not change)
time_interval = 30  # Time interval in seconds to wait before sending another POST request

# Track Brute packets
ssh_brute_tracker = defaultdict(int)
ftp_brute_tracker = defaultdict(int)
BRUTE_THRESHOLD = 10

# Track Scan packets
port_scan_tracker = defaultdict(lambda: {"ports": set(), "timestamps": []})
PORTSCAN_WINDOW = 5  # seconds
PORTSCAN_THRESHOLD = 50  # unique ports in short time


# Track SYN packets
syn_flood_tracker = defaultdict(lambda: {"count": 0, "first_seen": time.time()})
FLOOD_WINDOW = 1  # seconds
FLOOD_THRESHOLD = 400  # number of SYNs within the time window to be flagged

# Track Slowlor packets
slowloris_tracker = defaultdict(lambda: {"count": 0, "first_seen": time.time()})
SLOWLORIS_WINDOW = 30  # seconds
SLOWLORIS_THRESHOLD = 20  # SYNs to same IP:port from 1 IP in this window

## BotNet Detection
botnet_tracker = defaultdict(lambda: {"port": 0, "count": 1, "first_seen": time.time()})
BOTNET_WINDOW = 3  # seconds
BOTNET_THRESHOLD = 50  # SYNs to same IP:port from 1 IP in this window

# Track UDP packets
# udp_tracker = defaultdict(lambda: {"count": 0, "timestamp": time.time()})

# Brute force PORTS
monitored_brute_ports = [20, 21, 22, 3000]  # You can add 80, 443, etc.


def send_detection_occure(url, data):
    try:
        response = requests.post(url, json=data, timeout=2)
        if response.status_code == 429:
            print("[WARN] Rate limit hit on Flask server.")
        elif not response.ok:
            print(f"[WARN] POST failed: {response.status_code} {response.text}")
    except Exception as e:
        print(f"[WARN] POST request failed: {e}")


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

def match_rule(packet, rules):
    global port_scan_tracker, udp_tracker, ssh_brute_tracker, ftp_brute_tracker, last_post_request, time_interval
    try:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = packet.transport_layer if hasattr(packet, 'transport_layer') and packet.transport_layer else "UNKNOWN"
            payload = packet.get_raw_packet()
            now = time.time()

            # Rule Matching Logic (Snort-style and basic)
            for rule in rules:
                if rule.startswith("alert"):
                    parts = rule.split(None, 7)
                    if len(parts) < 8:
                        continue
                    _, rule_proto, rule_src, rule_src_port, arrow, rule_dst, rule_dst_port, options = parts
                    if rule_proto.lower() != proto.lower():
                        continue
                    if rule_src.lower() != "any" and rule_src != src_ip:
                        continue
                    if rule_dst.lower() != "any" and rule_dst != dst_ip:
                        continue
                    packet_dst_port = None
                    if proto.lower() == "tcp" and hasattr(packet, 'tcp'):
                        packet_dst_port = packet.tcp.dstport
                    elif proto.lower() == "udp" and hasattr(packet, 'udp'):
                        packet_dst_port = packet.udp.dstport
                    if rule_dst_port.lower() != "any" and packet_dst_port != rule_dst_port:
                        continue
                    flags_search = re.search(r'flags:\s*([^;]+);', options)
                    if flags_search:
                        expected_flags = flags_search.group(1).strip()
                        flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20, 'E': 0x40, 'C': 0x80}
                        expected_mask = sum(flag_map[ch] for ch in expected_flags if ch in flag_map)
                        if not hasattr(packet, 'tcp'):
                            continue
                        actual_mask = int(packet.tcp.flags, 16)
                        if actual_mask != expected_mask:
                            continue
                    msg_search = re.search(r'msg:\s*"(.*?)";', options)
                    msg = msg_search.group(1) if msg_search else "Alert triggered"
                    

                    if "SSH Brute Force" in msg:
                        key = (src_ip, dst_ip)
                        tracker = ssh_brute_tracker
                        tracker[key] += 1
                        if tracker[key] >= BRUTE_THRESHOLD:
                            if not last_post_request or now - last_post_request > time_interval:
                                detection_details = {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "intrusion_type": "SSH",
                                    "timestamp": now
                                }
                                send_detection_occure(f"http://localhost:{IDS_SERVER_PORT}/api/ids/trigger-intrusion", detection_details)
                                print(f"[RECORD] {msg} Detected! {BRUTE_THRESHOLD} attempts from {src_ip} to {dst_ip}")
                                tracker[key] = 0
                                last_post_request = now

                    elif "FTP Brute Force" in msg:
                        key = (src_ip, dst_ip)
                        tracker = ftp_brute_tracker
                        tracker[key] += 1
                        if tracker[key] >= BRUTE_THRESHOLD:
                            if not last_post_request or now - last_post_request > time_interval:
                                #now = time.time()
                                detection_details = {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "intrusion_type": "FTP",
                                    "timestamp": now
                                }
                                send_detection_occure(f"http://localhost:{IDS_SERVER_PORT}/api/ids/trigger-intrusion", detection_details)
                                print(f"[RECORD] {msg} Detected! {BRUTE_THRESHOLD} attempts from {src_ip} to {dst_ip}")
                                tracker[key] = 0
                                last_post_request = now

                    # This line will run regardless of the type
                    #print(f"[ALERT] {msg} Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}")

                else:
                    rule_parts = rule.split()
                    if len(rule_parts) < 4:
                        continue
                    rule_src, rule_dst, rule_proto, rule_payload = rule_parts[:4]
                    if (rule_src != '*' and rule_src != src_ip): continue
                    if (rule_dst != '*' and rule_dst != dst_ip): continue
                    if (rule_proto != '*' and rule_proto.lower() != proto.lower()): continue
                    if rule_payload != '*' and not re.search(rule_payload, str(payload)): continue
                    print(f"[ALERT] Rule matched! Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}")


            if proto == "TCP" and hasattr(packet, 'tcp') and hasattr(packet.tcp, "flags"):
                try:
                    flags_int = int(packet.tcp.flags, 16)
                except Exception:
                    flags_int = 0

                if flags_int == 0x02:  # SYN only
                    dst_port = int(packet.tcp.dstport)
                    now = time.time()

                    # print(f"[NOT MALICIOUS] SYN Packet -> Src: {src_ip}, Dst: {dst_ip}:{dst_port}, Time: {now}")

                    #### ✅ PORT SCAN DETECTION ####
                    entry = port_scan_tracker[src_ip]
                    entry["timestamps"] = [t for t in entry["timestamps"] if now - t < PORTSCAN_WINDOW]
                    entry["timestamps"].append(now)
                    entry["ports"].add(dst_port)

                    if len(entry["ports"]) > PORTSCAN_THRESHOLD and len(entry["timestamps"]) > PORTSCAN_THRESHOLD:
                        if not last_post_request or now - last_post_request > time_interval:
                            detection_details = {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "intrusion_type": "Portscan",
                                "timestamp": now
                            }
                            send_detection_occure(f"http://localhost:{IDS_SERVER_PORT}/api/ids/trigger-intrusion", detection_details)
                            print(f"[RECORD] PORT SCAN detected! Source: {src_ip}")
                            port_scan_tracker[src_ip] = {"ports": set(), "timestamps": []}
                            last_post_request = now


                    #### ✅ SYN FLOOD DETECTION ####
                    flood_key = (src_ip, dst_ip, dst_port)
                    flood_entry = syn_flood_tracker[flood_key]

                    if now - flood_entry["first_seen"] <= FLOOD_WINDOW:
                        flood_entry["count"] += 1
                        if flood_entry["count"] > FLOOD_THRESHOLD:
                            if not last_post_request or now - last_post_request > time_interval:
                                detection_details = {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "intrusion_type": "DoS",
                                    "timestamp": now
                                }
                                send_detection_occure(f"http://localhost:{IDS_SERVER_PORT}/api/ids/trigger-intrusion", detection_details)
                                # print(f"[RECORD] SYN Flood detected! Src: {src_ip}, Dst: {dst_ip}:{dst_port}, Count: {flood_entry['count']}")
                                syn_flood_tracker[flood_key] = {"count": 0, "first_seen": now}
                                last_post_request = now
                    else:
                        syn_flood_tracker[flood_key] = {"count": 1, "first_seen": now}

                    #### ✅ SLOWLORIS DETECTION ####
                    slowloris_key = (src_ip, dst_ip, dst_port)
                    entry = slowloris_tracker[slowloris_key]

                    if now - entry["first_seen"] <= SLOWLORIS_WINDOW:
                        entry["count"] += 1
                        if entry["count"] > SLOWLORIS_THRESHOLD:
                            if not last_post_request or now - last_post_request > time_interval:
                                detection_details = {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "intrusion_type": "DoS",
                                    "timestamp": now
                                }
                                send_detection_occure(f"http://localhost:{IDS_SERVER_PORT}/api/ids/trigger-intrusion", detection_details)
                                # print(f"[RECORD] Slowloris attack detected! Src: {src_ip}, Dst: {dst_ip}:{dst_port}, Count: {entry['count']}")
                                slowloris_tracker[slowloris_key] = {"count": 0, "first_seen": now}
                                last_post_request = now
                    else:
                        slowloris_tracker[slowloris_key] = {"count": 1, "first_seen": now}

                    #### ✅ BOTNET DETECTION ####
                    botnet_key = (dst_ip, dst_port)
                    botnet_entry = botnet_tracker[botnet_key]

                    if now - botnet_entry["first_seen"] <= BOTNET_WINDOW:
                        botnet_entry["count"] += 1
                        # print(botnet_entry["count"], botnet_key)
                        if botnet_entry["count"] > BOTNET_THRESHOLD:
                            if not last_post_request or now - last_post_request > time_interval:
                                detection_details = {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "intrusion_type": "Bot",
                                    "timestamp": now
                                }
                                send_detection_occure(f"http://localhost:{IDS_SERVER_PORT}/api/ids/trigger-intrusion", detection_details)
                                print(f"[RECORD] POSSIBLE BOTNET ATTACK: TOO MANY SYN Packets from {src_ip} to {dst_ip}:{dst_port}")
                                botnet_tracker[botnet_key] = {"port": dst_port, "count": 1, "first_seen": now}
                                last_post_request = now
                    else:
                        botnet_tracker[botnet_key] = {"port": dst_port, "count": 1, "first_seen": now}


                if flags_int == 0x02:   #### ✅ BOTNET DETECTION ####
                    src_port = int(packet.tcp.srcport)
                    now = time.time()
                    
                    synack_key = (src_ip, src_port)
                    entry = botnet_tracker[synack_key]
                    if now - entry.get("first_seen", now) <= BOTNET_WINDOW:
                        entry["count"] += 1
                        if entry["count"] > BOTNET_THRESHOLD:
                            if not last_post_request or now - last_post_request > time_interval:
                                detection_details = {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "intrusion_type": "Bot",
                                    "timestamp": now
                                }
                                send_detection_occure(f"http://localhost:{IDS_SERVER_PORT}/api/ids/trigger-intrusion", detection_details)
                                print(f"[RECORD] POSSIBLE BOTNET ATTACK TOO MANY SYN-ACK Packets from {src_ip}:{src_port} in Time={now}")
                                botnet_tracker[synack_key] = {"port": src_port, "count": 1, "first_seen": now}
                                last_post_request = now
                    else:
                        botnet_tracker[synack_key] = {"port": src_port, "count": 1, "first_seen": now}

    except Exception as e:
        print(f"Error processing packet: {e}")

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
    INTERFACE = "\\Device\\NPF_{0B5347F4-28B6-47E3-9652-8173F5B57B74}"  # Replace with your Linux interface, e.g., eth0, ens33, wlan0
    RULE_FILES = ["rules.rules", "BasicRule.txt"]
    start_ids(INTERFACE, RULE_FILES)
