from scapy.all import sniff, IP, TCP, Raw, get_if_list
import re
import requests
import os

# VirusTotal API Key (replace with your own API key)
VIRUSTOTAL_API_KEY = "-your API Key-"

# Log file for captured packets
LOG_FILE = "captured_packets.log"

# 1. Packet Sniffing Functionality
def packet_callback(packet):
    if packet.haslayer(IP):  # Check for IP layer only
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto  # Get protocol number (6 for TCP, 17 for UDP, etc.)

        # Try decoding payload if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            print(f"[+] Packet {ip_src} -> {ip_dst}: {payload}")
            # Attempt to detect sensitive information in the payload
            detect_sensitive_information(payload)
    else:
        print(f"[!] Ignored non-IP packet: {packet.summary()}")

# Function to decode payload with error handling
# def decode_payload(payload):
#     try:
#         # Attempt to decode using utf-8, with replace for un-decodable characters
#         return payload.decode("utf-8", errors="replace")
#     except UnicodeDecodeError:
#         # If utf-8 fails, try utf-8-sig or other common encodings
#         try:
#             return payload.decode("utf-8-sig", errors="replace")
#         except UnicodeDecodeError:
#             return payload.decode("latin1", errors="replace")  # Fallback to latin1 if all else fails

# 2. Log Packets to a File
def log_packet(ip_src, ip_dst, protocol, payload):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}\n")
        log_file.write(f"Payload:\n{payload}\n")
        log_file.write("=" * 50 + "\n")

# 3. Detect Sensitive Information (advanced regex for common patterns)
def detect_sensitive_information(payload):
    # Basic regex patterns for sensitive data
    username_pattern = re.compile(r"(username|user|uname|login)[\s:=]*([\w\d@._-]+)", re.IGNORECASE)
    password_pattern = re.compile(r"(password|pass|pwd)[\s:=]([\w\d@#$%^&()_+]+)", re.IGNORECASE)
    email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    credit_card_pattern = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

    if username_match := username_pattern.search(payload):
        print(f"[!] Possible Username Detected: {username_match.group(2)}")
    if password_match := password_pattern.search(payload):
        print(f"[!] Possible Password Detected: {password_match.group(2)}")
    if email_match := email_pattern.search(payload):
        print(f"[!] Possible Email Detected: {email_match.group()}")
    if credit_card_match := credit_card_pattern.search(payload):
        print(f"[!] Possible Credit Card Detected: {credit_card_match.group()}")

# 4. Capture Network Traffic
def start_sniffing(interface="eth0", packet_count=100):
    print(f"Starting packet sniffer on interface: {interface}")
    try:
        # Sniff all TCP traffic (no filters applied)
        sniff(
            iface=interface,
            prn=packet_callback,
            store=0,
            count=packet_count
        )
    except Exception as e:
        print(f"[!] Error starting packet sniffer: {e}")
        print("[!] Ensure you have entered a valid network interface and have administrator privileges.")

# 5. Analyze Files with VirusTotal
def analyze_file_virus_total(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)
        
    if response.status_code == 200:
        result = response.json()
        print("Malware Analysis Result:", result)
    else:
        print("VirusTotal Analysis Error:", response.status_code)

# 6. Analyze Directory Files
def analyze_directory(directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Analyzing file: {file_path}")
            analyze_file_virus_total(file_path)

# Main Program
if __name__ == "__main__":

    # Set up packet sniffing
    interface = input("Enter network interface to sniff (e.g., eth0, wlan0): ")
    packet_limit = int(input("Enter the number of packets to capture (e.g., 100): "))
    start_sniffing(interface, packet_count=packet_limit)

    # Optional Malware Analysis
    directory_path = input("Enter directory path for malware analysis (or leave blank to skip): ")
    if directory_path:
        analyze_directory(directory_path)
