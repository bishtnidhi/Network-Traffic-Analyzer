# Network-Traffic-Analyzer
network_traffic_capture.py:  The main Python script that captures network traffic. Uses Scapy for sniffing packets and processing network traffic. Tracks suspicious activity such as DNS queries, IRC traffic, and port scanning. 
# Network Traffic Capture with Suspicious Activity Detection

This project is a network traffic capture tool written in Python using the **Scapy** library. The tool is designed to capture network packets, analyze them for suspicious activity, and provide real-time feedback to the user. It also includes a simple GUI for visualizing captured packet data.

## Features

- **Packet Capture**: Sniffs network traffic on your local network interface.
- **Suspicious Activity Detection**:
  - DNS queries that might indicate suspicious activity.
  - IRC traffic detected on port 6667.
  - Port scanning behavior (e.g., many connections to different ports from a single IP).
- **Real-time Statistics**: Displays total packets, total bytes, and protocol distribution (TCP, UDP, DNS) in the GUI.
- **Top Talkers**: Displays the top 5 source IP addresses that have generated the most traffic.
- **Alert System**: Plays a beep sound and sends an email when suspicious activity is detected.
- **PCAP File Output**: Saves captured packets in a **PCAP** file, which can be analyzed later using tools like Wireshark.

## Requirements

To run this script, you need to have the following Python packages installed:

- **Scapy**: A powerful Python library used for network packet manipulation.
- **Tkinter**: The standard GUI toolkit for Python (usually comes pre-installed with Python).
- **Whois**: A library used to perform WHOIS lookups for IP addresses.
- **smtplib**: For sending email alerts (uses your email credentials).
- **winsound**: A module for Windows sound notifications (to alert suspicious activities).

You can install the required dependencies using `pip`:

```bash
pip install scapy whois
