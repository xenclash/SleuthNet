# SleuthNet Version 1.0

SleuthNet is a lightweight, Python based Network Traffic Analysis and Intrusion Detection System. It monitors live traffic and raises real-time terminal alerts for SYN floods, port scans, and traffic spikes. (Project is still a WIP)

## Features

- **SYN Flood Detection** - flags IPs sending excessive SYN packets within a sliding time window.
- **Port Scan Detection** - flags IPs touching an unusual number of distinct ports within a sliding time window.
- **Traffic Spike Detection** - flags IPs generating abnormal packet volume within a sliding time window.
- **Alert Cooldown** - suppresses repeat alerts per IP/attack type so logs stay readable during a sustained attack.
- **Thread-Safe & Efficient** - single-lock packet analysis with a kernel-level BPF filter (`ip`) to cut overhead.
- **Automatic Cleanup** - forgets inactive IPs on a timer to keep memory bounded.
- **Configurable** - tune thresholds, window, interface, and log file via CLI flags.
- **Rotating Logs** - alerts are written to both the terminal and a rotating log file.

## Requirements

- Python
- [Scapy](https://scapy.net/)
- Root privileges (required to sniff a network interface)

Install dependencies:

```bash
pip install scapy
```

## Usage

```bash
sudo python3 SleuthNet.py -i eth0
```

| Flag | Default | Description |
|---|---|---|
| `-i, --interface` | `eth0` | Network interface to sniff on |
| `--syn-threshold` | `100` | SYNs per window to flag a flood |
| `--port-threshold` | `50` | Unique ports per window to flag a scan |
| `--traffic-threshold` | `100` | Packets per window to flag a spike |
| `--window` | `10` | Sliding detection window, in seconds |
| `--log-file` | `sleuthnet.log` | Log file path |

## Output

Alerts are timestamped and printed to both the terminal and the log file:

```
2026-07-03 21:14:02 WARNING Possible port scan detected from 192.168.1.x (63 ports in 10s)
```

## License

MIT License

---

All code is made by scratch, then used Claude to assist with enhancements applied to debugging, and optimization.
