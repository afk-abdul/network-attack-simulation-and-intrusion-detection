import scapy.all as scapy
import re
import time
from collections import Counter
import os

os.makedirs("logs", exist_ok=True)

LOG_FILE = "logs/network_traffic.log"
scan_counts = Counter()
ddos_counts = Counter()

# Phishing and SQL Injection patterns
PHISHING_PATTERNS = [
    r"(?:https?://)?(?:www\.)?(?!example\.com)[a-z0-9-]+\.(?:tk|ml|ga|cf|gq)",
    r"(?:https?://)?.*\.(?:\d{1,3}\.){3}\d{1,3}",
    r"(?:https?://)?.*(login|verify|update).*",
    r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z]{2,}){1,2}/.*(login|account|bank|payment).*",
    r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z]{2,}){1,2}/.*\?(?:user|email|pass).*",
    r"(\.zip|\.exe|\.scr)\b",
    r"(?:https?://)(?:www\.)?[a-z0-9-]+(?:\.[a-z]{2,}){1,2}/.*(reset|recover|support).*",
    r"(?:https?://)?(?:www\.)?(?!example\.com)[a-z0-9-]+\.(?:cn|ru|in|xyz|co|co\.uk)",
    r"(?:https?://)?(?:www\.)?[a-z0-9-]+\.(?:com|org|net)/.*(admin|config|system).*",
]

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\bOR\b.+\b=\b",
    r"UNION(\s+ALL)?(\s+SELECT)",
    r"SELECT.+FROM",
    r"INSERT(\s+INTO)?\s",
    r"UPDATE\s.+\sSET\s",
    r"DELETE\s+FROM",
    r"DROP\s+TABLE",
    r"EXEC(\s|\+)+(s|x)p\w+",
    r"OR\s+1=1",
    r"' OR '1'='1",
    r"admin' --",
]

#save all data in the log file
def log_packet(log_type, details):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {log_type}: {details}\n"
    print(log_entry.strip())
    with open(LOG_FILE, "a") as log:
        log.write(log_entry)


#detect the type of scan
def detect_scan_type(packet):
    flags = packet[scapy.TCP].flags
    if flags == "SA":
        return "TCP CONNECT SCAN"
    elif flags == 0:
        return "NULL SCAN"
    elif flags == "FPU":
        return "XMAS SCAN"
    elif flags == "F":
        return "FIN SCAN"
    return None

#main packet callback function
def packet_callback(packet):
    if not packet.haslayer(scapy.IP):
        return

    #get packet data
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    log_details = f"From {src_ip} to {dst_ip}"
    is_attack = False

    payload = ""
    if packet.haslayer(scapy.Raw):
        try:
            payload = packet[scapy.Raw].load.decode(errors="ignore")
        except:
            payload = ""

    # Phishing Detection
    if payload and any(re.search(pattern, payload, re.IGNORECASE) for pattern in PHISHING_PATTERNS):
        log_packet("PHISHING ATTEMPT", f"From {src_ip} | Suspicious URL: {payload}")
        is_attack = True

    # SQL Injection Detection
    elif payload and any(re.search(pattern, payload, re.IGNORECASE) for pattern in SQLI_PATTERNS):
        log_packet("SQL INJECTION ATTEMPT", f"From {src_ip} | Payload: {payload}")
        is_attack = True

    # Port Scan Detection
    elif packet.haslayer(scapy.TCP):
        scan_type = detect_scan_type(packet)
        if scan_type:
            log_packet(f"{scan_type} DETECTED", log_details)
            is_attack = True

    # UDP Scan Detection
    elif packet.haslayer(scapy.UDP):
        scan_counts[(src_ip, dst_ip, 'udp')] += 1
        if scan_counts[(src_ip, dst_ip, 'udp')] == 10:
            log_packet("UDP SCAN DETECTED", log_details)
            scan_counts[(src_ip, dst_ip, 'udp')] = 0
            is_attack = True

    # DDoS Detection
    ddos_counts[dst_ip] += 1
    if ddos_counts[dst_ip] > 200:
        log_packet("DDoS ATTACK DETECTED", f"Target: {dst_ip} (Over 200 packets!)")
        ddos_counts[dst_ip] = 0
        is_attack = True

    # Normal Packet
    if not is_attack:
        if packet.haslayer(scapy.TCP):
            log_details += f" | TCP Port: {packet[scapy.TCP].dport}"
        elif packet.haslayer(scapy.UDP):
            log_details += f" | UDP Port: {packet[scapy.UDP].dport}"
        elif packet.haslayer(scapy.ICMP):
            log_details += " | ICMP Request"
        log_packet("NORMAL PACKET", log_details)

print(f"Starting packet monitoring")
import platform

# Choose interface dynamically
iface = None
if platform.system() == "Windows":
    iface = [i for i in scapy.get_if_list() if "NPF_Loopback" not in i][0] # or get via scapy.get_if_list()
else:
    iface = "eth0"  # or "wlan0", or scapy.get_if_list()[0]

scapy.sniff(iface=iface, filter="tcp or udp", prn=packet_callback, store=False)

