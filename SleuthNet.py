import argparse
import os
import sys
import time
import threading
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict, deque

import scapy.all as scapy

# Basic user interface header
print("""
 ░▒▓███████▓▒░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░    ░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░
░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░  ░▒▓█▓▒░

                        | Network Traffic Analysis & Intrusion Detection System version 1.0 |
                                       | 2026 Created by @xenclash on Github |
""")

# Thread safe dictionary for suspected IPs, and timestamps stored in sliding.
# windows (deques) so counts decay naturally instead of growing forever.
suspected_ips = defaultdict(lambda: {
    "syn_timestamps": deque(),
    "port_timestamps": deque(),  # (timestamp, port) pairs
    "traffic_timestamps": deque(),
    "last_seen": 0.0,
    "last_alert": {}  # alert_type -> last time it fired, for cooldown
})
lock = threading.Lock()

# Defaults can be overridden via CLI args in main()
SYN_FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 50
TRAFFIC_SPIKE_THRESHOLD = 100
DETECTION_WINDOW = 10        # Seconds sliding window for all three detectors
ALERT_COOLDOWN = 30          # Seconds between repeat alerts for the same IP/type
INACTIVE_TIMEOUT = 300       # Seconds of silence before an IP is forgotten


def _prune(dq, now, window, key=lambda x: x):
    while dq and now - key(dq[0]) > window:
        dq.popleft()


def _maybe_alert(entry, alert_type, now, message):
    last = entry["last_alert"].get(alert_type, 0)
    if now - last >= ALERT_COOLDOWN:
        entry["last_alert"][alert_type] = now
        logging.warning(message)


def _check_syn_flood(entry, ip_src, now):
    entry["syn_timestamps"].append(now)
    _prune(entry["syn_timestamps"], now, DETECTION_WINDOW)
    count = len(entry["syn_timestamps"])
    if count > SYN_FLOOD_THRESHOLD:
        _maybe_alert(entry, "syn_flood", now,
                     f"SYN flood detected from {ip_src} ({count} SYNs in {DETECTION_WINDOW}s)")


def _check_port_scan(entry, ip_src, port, now):
    entry["port_timestamps"].append((now, port))
    _prune(entry["port_timestamps"], now, DETECTION_WINDOW, key=lambda item: item[0])
    unique_ports = {p for _, p in entry["port_timestamps"]}
    if len(unique_ports) > PORT_SCAN_THRESHOLD:
        _maybe_alert(entry, "port_scan", now,
                     f"Possible port scan detected from {ip_src} ({len(unique_ports)} ports in {DETECTION_WINDOW}s)")


def _check_traffic_spike(entry, ip_src, now):
    entry["traffic_timestamps"].append(now)
    _prune(entry["traffic_timestamps"], now, DETECTION_WINDOW)
    count = len(entry["traffic_timestamps"])
    if count > TRAFFIC_SPIKE_THRESHOLD:
        _maybe_alert(entry, "traffic_spike", now,
                     f"Traffic spike detected from {ip_src} ({count} packets in {DETECTION_WINDOW}s)")


def cleanup_suspected_ips():
    while True:
        time.sleep(60)
        now = time.time()
        with lock:
            to_delete = [ip for ip, data in suspected_ips.items() if now - data["last_seen"] > INACTIVE_TIMEOUT]
            for ip in to_delete:
                del suspected_ips[ip]


def analyze_packet(packet):
    if not packet.haslayer(scapy.IP):
        return
    ip_src = packet[scapy.IP].src
    now = time.time()
    with lock:
        entry = suspected_ips[ip_src]
        entry["last_seen"] = now
        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            if tcp.flags == "S":
                _check_syn_flood(entry, ip_src, now)
            _check_port_scan(entry, ip_src, tcp.dport, now)
        _check_traffic_spike(entry, ip_src, now)


def packet_sniffer(interface):
    # BPF filter so non-IP traffic never reaches analyze_packet
    scapy.sniff(iface=interface, prn=analyze_packet, store=False, filter="ip")


def start_sniffing(interface):
    logging.info(f"[*] Starting packet sniffer on interface {interface}...")
    try:
        packet_sniffer(interface)
    except OSError as exc:
        logging.error(f"[!] Failed to sniff on interface {interface}: {exc}")


def parse_args():
    parser = argparse.ArgumentParser(description="SleuthNet - lightweight network IDS/IPS")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on")
    parser.add_argument("--syn-threshold", type=int, default=SYN_FLOOD_THRESHOLD, help="SYNs per window to flag a flood")
    parser.add_argument("--port-threshold", type=int, default=PORT_SCAN_THRESHOLD, help="Unique ports per window to flag a scan")
    parser.add_argument("--traffic-threshold", type=int, default=TRAFFIC_SPIKE_THRESHOLD, help="Packets per window to flag a spike")
    parser.add_argument("--window", type=int, default=DETECTION_WINDOW, help="Sliding window in seconds for all detectors")
    parser.add_argument("--log-file", default="sleuthnet.log", help="File to write logs to (in addition to stdout)")
    return parser.parse_args()


def configure_logging(log_file):
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


if __name__ == "__main__":
    args = parse_args()
    configure_logging(args.log_file)

    SYN_FLOOD_THRESHOLD = args.syn_threshold
    PORT_SCAN_THRESHOLD = args.port_threshold
    TRAFFIC_SPIKE_THRESHOLD = args.traffic_threshold
    DETECTION_WINDOW = args.window

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logging.error("[!] SleuthNet requires root privileges to capture packets. Try running with sudo.")
        sys.exit(1)

    if args.interface not in scapy.get_if_list():
        logging.error(f"[!] Interface '{args.interface}' not found. Available: {', '.join(scapy.get_if_list())}")
        sys.exit(1)

    threading.Thread(target=cleanup_suspected_ips, daemon=True).start()
    sniffing_thread = threading.Thread(target=start_sniffing, args=(args.interface,), daemon=True)
    sniffing_thread.start()

    try:
        while sniffing_thread.is_alive():
            sniffing_thread.join(timeout=1)
    except KeyboardInterrupt:
        logging.info("[*] Stopping SleuthNet...")
        sys.exit(0)
