# SleuthNet
SleuthNet is a Python based Network Traffic Analysis and Intrusion Detection System. It monitors live network traffic for suspicious activity such as SYN floods, port scans, and traffic spikes, providing real time alerts in your terminal.

## Features

- SYN Flood Detection: Identifies potential SYN flood attacks by tracking excessive SYN packets from a single IP.
- Port Scan Detection: Detects port scanning attempts by monitoring connections to multiple ports from the same IP.
- Traffic Spike Detection: Alerts when a host sends an unusually high number of packets in a short time window.
- Thread-Safe & Efficient: Uses threading and locking for safe, concurrent analysis.
- Automatic Cleanup: Periodically removes inactive IPs from memory.
- User Interface: Displays a stylish ASCII-art banner on startup.

## Requirements

- Python
- Scapy

Install Scapy with:
bash

*Note* Root privileges are required to sniff network traffic.

Run the script with:
sudo python3 SleuthNet.py

## Outputs

- Alerts and logs are printed to the terminal with timestamps.
- The ASCII-art banner appears at startup.

## Running
-Do "sudo python3 SleuthNet.py" to run the script.

## Disclaimer Warning!!

This tool is for educational and authorized security testing purposes only, I am not responsible for how it's used.
Please do not use on networks without permission.
