import scapy.all as scapy
import time
import threading
from collections import defaultdict
import logging

# basic user interface header
print("""
 ░▒▓███████▓▒░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
 ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░    ░▒▓█▓▒░     
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░  ░▒▓█▓▒░     
                                                                                                                       
                                Network Traffic Analysis and Intrusion Detection System
                                  | 2025 Created by Marcelo M / @Xenclash on Github |                                                                    
""")
      
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

# Thread-safe dictionary for suspected IPs
suspected_ips = defaultdict(lambda: {
    "syn_count": 0,
    "port_count": 0,
    "traffic_count": 0,
    "ports": set(),
    "timestamps": [],
    "last_seen": 0
})
lock = threading.Lock()

SYN_FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 50
TRAFFIC_SPIKE_THRESHOLD = 100
TRAFFIC_SPIKE_WINDOW = 10  # seconds

def syn_flood_detection(packet, ip_src):
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
        with lock:
            suspected_ips[ip_src]["syn_count"] += 1
            suspected_ips[ip_src]["last_seen"] = time.time()
            if suspected_ips[ip_src]["syn_count"] > SYN_FLOOD_THRESHOLD:
                logging.warning(f"SYN flood detected from {ip_src}!")

def port_scan_detection(packet, ip_src):
    if packet.haslayer(scapy.TCP):
        port = packet[scapy.TCP].dport
        with lock:
            suspected_ips[ip_src]["ports"].add(port)
            suspected_ips[ip_src]["port_count"] = len(suspected_ips[ip_src]["ports"])
            suspected_ips[ip_src]["last_seen"] = time.time()
            if suspected_ips[ip_src]["port_count"] > PORT_SCAN_THRESHOLD:
                logging.warning(f"Possible port scan detected from {ip_src}!")

def traffic_spike_detection(packet, ip_src):
    now = time.time()
    with lock:
        suspected_ips[ip_src]["timestamps"].append(now)
        suspected_ips[ip_src]["last_seen"] = now
        # Remove timestamps older than TRAFFIC_SPIKE_WINDOW
        suspected_ips[ip_src]["timestamps"] = [
            t for t in suspected_ips[ip_src]["timestamps"] if now - t < TRAFFIC_SPIKE_WINDOW
        ]
        if len(suspected_ips[ip_src]["timestamps"]) > TRAFFIC_SPIKE_THRESHOLD:
            logging.warning(f"Traffic spike detected from {ip_src}!")

def cleanup_suspected_ips():
    while True:
        time.sleep(60)
        now = time.time()
        with lock:
            to_delete = [ip for ip, data in suspected_ips.items() if now - data["last_seen"] > 300]
            for ip in to_delete:
                del suspected_ips[ip]

def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        syn_flood_detection(packet, ip_src)
        port_scan_detection(packet, ip_src)
        traffic_spike_detection(packet, ip_src)

def packet_sniffer(interface):
    scapy.sniff(iface=interface, prn=analyze_packet, store=False)

def start_sniffing(interface="eth0"):
    logging.info(f"[*] Starting packet sniffer on interface {interface}...")
    packet_sniffer(interface)

if __name__ == "__main__":
    interface = "eth0"  # Optionally, parse from sys.argv
    threading.Thread(target=cleanup_suspected_ips, daemon=True).start()
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniffing_thread.start()
