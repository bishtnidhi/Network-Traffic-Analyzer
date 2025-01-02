import pandas as pd
from scapy.all import sniff, wrpcap, Ether, rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import whois
import tkinter as tk
from tkinter import ttk
import sys
import time
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText
import winsound  # For Windows sound notifications

data = []  # Captured packet data
suspicious_activity_found = False  # Flag for suspicious activity
packets = []  # List to store captured packets for PCAP

# Variables for real-time statistics
total_packets = 0
total_bytes = 0
protocol_stats = defaultdict(int)
top_talkers = defaultdict(int)

# Dictionary to track connection attempts per source IP
ip_port_attempts = defaultdict(lambda: defaultdict(int))

# Thresholds for port scanning detection (e.g., 5 attempts to different ports within 5 seconds)
PORT_SCAN_THRESHOLD = 5
PORT_SCAN_TIME_WINDOW = 5  # seconds

# Function to send an alert email
def send_alert_email(message):
    sender_email = "youremail@example.com"  # Update with your email
    receiver_email = "receiver@example.com"  # Update with the receiver email
    password = "your_email_password"  # Update with your email password
    
    msg = MIMEText(message)
    msg["Subject"] = "Network Traffic Alert"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print("Alert email sent!")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

# Function to play a beep sound (works on Windows)
def play_beep_sound():
    try:
        winsound.Beep(1000, 500)  # Frequency 1000 Hz, duration 500 ms
    except Exception as e:
        print(f"Error playing beep sound: {e}")

# Packet callback function that processes each packet
def packet_callback(packet):
    global suspicious_activity_found, packets, ip_port_attempts, total_packets, total_bytes, protocol_stats, top_talkers

    suspicious_activity = False  # Flag for suspicious activity per packet
    dns_query = None  # Initialize dns_query

    # Track timestamps of packet capture
    current_time = time.time()

    # Check if the packet contains an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # TCP packets
        if protocol == 6 and TCP in packet:  # TCP packets
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Count connection attempts to a particular port from source IP
            ip_port_attempts[src_ip][dst_port] += 1

            # Check if the source IP has exceeded the threshold for port scanning
            if ip_port_attempts[src_ip][dst_port] > PORT_SCAN_THRESHOLD:
                print(f"Potential Port Scan detected from {src_ip} to port {dst_port} (Threshold exceeded)")
                suspicious_activity = True
                send_alert_email(f"Port Scan detected: {src_ip} scanning port {dst_port}")
                play_beep_sound()  # Play beep sound on suspicious activity

        # UDP packets
        elif protocol == 17 and UDP in packet:  # UDP packets
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # Here you can add any condition based on UDP if needed

        # Checking for suspicious activity such as DNS queries or known patterns
        if DNS in packet and DNSQR in packet:
            dns_query = packet[DNSQR].qname.decode() if DNSQR in packet else None
            if dns_query:
                print(f"Suspicious DNS query detected: {dns_query}")
                suspicious_activity = True
                play_beep_sound()  # Play beep sound on suspicious DNS query

        if src_port == 6667 or dst_port == 6667:
            print("Potential IRC traffic detected (port 6667)")
            suspicious_activity = True
            play_beep_sound()  # Play beep sound on IRC traffic

        # Append data to global list for GUI and PCAP output
        data.append([src_ip, dst_ip, src_port, dst_port, "TCP" if protocol == 6 else "UDP", dns_query])
        packets.append(packet)  # Store packet in list

        # Update real-time statistics
        total_packets += 1
        total_bytes += len(packet)

        # Track protocol stats
        if protocol == 6:
            protocol_stats["TCP"] += 1
        elif protocol == 17:
            protocol_stats["UDP"] += 1
        elif DNS in packet:
            protocol_stats["DNS"] += 1

        # Track top talkers (IPs)
        top_talkers[src_ip] += len(packet)

        # Mark if suspicious activity is found
        if suspicious_activity:
            suspicious_activity_found = True

        update_gui()  # Update GUI with latest packet data

# Function to update the GUI with traffic statistics
def update_gui():
    # Update GUI window with live captured packet data
    tree.delete(*tree.get_children())  # Clear existing data in the tree
    for i, packet in enumerate(data):
        tree.insert("", "end", text=str(i+1), values=packet)

    # Update traffic statistics
    stats_text.set(f"Total Packets: {total_packets}\n"
                   f"Total Bytes: {total_bytes}\n"
                   f"TCP: {protocol_stats['TCP']}\n"
                   f"UDP: {protocol_stats['UDP']}\n"
                   f"DNS: {protocol_stats['DNS']}\n")

    # Show top talkers
    talkers_text.set("\nTop Talkers:\n")
    for ip, traffic in sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:5]:
        talkers_text.set(talkers_text.get() + f"{ip}: {traffic} bytes\n")

# WHOIS lookup (for IPs)
def get_whois_info(ip):
    try:
        return whois.whois(ip)
    except Exception as e:
        return f"Error: {str(e)}"

# GUI setup function
def show_gui():
    global tree, stats_text, talkers_text
    root = tk.Tk()
    root.title("Captured Network Traffic")

    tree = ttk.Treeview(root)
    tree["columns"] = ("Source IP", "Destination IP", "Source Port", "Destination Port", "Packet Type", "DNS Query")
    tree.heading("#0", text="Packet #")
    tree.column("#0", width=50, stretch=tk.NO)
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=150, stretch=tk.NO)

    tree.pack(expand=True, fill=tk.BOTH)

    # Label for traffic stats
    stats_text = tk.StringVar()
    stats_label = tk.Label(root, textvariable=stats_text, justify=tk.LEFT)
    stats_label.pack()

    # Label for top talkers
    talkers_text = tk.StringVar()
    talkers_label = tk.Label(root, textvariable=talkers_text, justify=tk.LEFT)
    talkers_label.pack()

    return root

# Stop packet capture and save PCAP
def stop_capture():
    global suspicious_activity_found, packets
    # If suspicious activity is found, do not print "No Suspicious traffic detected"
    if not suspicious_activity_found:
        print("No Suspicious traffic detected")  # Print only if no suspicious activity was found

    # Save the captured packets to a PCAP file with Ethernet link-layer type explicitly set
    wrpcap("captured_traffic.pcap", packets, linktype=1)  # linktype=1 corresponds to Ethernet
    print("Packets saved to captured_traffic.pcap")

    # Verify if packets exist before reading the .pcap file
    if len(packets) > 0:
        # Read and display the summary of the captured packets
        print("\nPacket Summary from captured_traffic.pcap:")
        captured_packets = rdpcap("captured_traffic.pcap")  # Read pcap file
        if len(captured_packets) > 0:
            for packet in captured_packets:
                print(packet.summary())  # Display packet summary
        else:
            print("No packets found in the pcap file.")
    else:
        print("No packets captured to save.")
    
    sys.exit()

if __name__ == "__main__":
    # Set the network interface to capture traffic from
    INTERFACE = "Wi-Fi"  # Change to your interface if needed

    # Set the filter expression to capture both TCP and UDP traffic
    FILTER = "tcp or udp"

    # Start the GUI first
    root = show_gui()

    # Start capturing network traffic using scapy
    print("Capturing network traffic...")

    try:
        # Start sniffing packets with a timeout of 30 seconds
        sniff(iface=INTERFACE, filter=FILTER, prn=packet_callback, store=False, timeout=30)

        # If no suspicious activity was detected during the sniffing
        stop_capture()

    except Exception as e:
        print(f"Error capturing traffic: {str(e)}")

    # Main loop for GUI
    root.mainloop()
