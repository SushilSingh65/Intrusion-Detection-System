from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from datetime import datetime
import socket
import enum_detector  # Keeps enum logic modular
import threading
import signal
import sys
from colorama import init, Fore, Style
import pygame
import ipaddress
from geoip_lookup import get_geo_info
from email_alert import send_email_alert

# === INIT ===
init()

# === Configuration ===
alert_log = "ids_alerts.txt"
ignored_ip = "192.168.18.139"
ignored_ip = "192.168.18.5"
ignored_ip = "192.168.153.84"
ignored_ip = "192.168.28.84" # Your own IP
ignored_ip = "192.168.18.19" # Your own IP

# Sensitive ports list (includes well-known services often scanned)
sensitive_ports = {
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 512, 513, 514, 873, 993, 995, 1080,
    1433, 1521, 1723, 2049, 2121, 3306, 3389, 5060, 5432, 5900, 6379,
    8080, 8443, 9000, 9090, 10000, 27017, 5000, 7001, 8000, 4444
}

# Trusted public cloud providers
trusted_ranges = [
    ipaddress.ip_network("104.16.0.0/12"),     # Cloudflare
    ipaddress.ip_network("172.217.0.0/16"),    # Google
    ipaddress.ip_network("35.0.0.0/8"),        # Google Cloud / AWS
    ipaddress.ip_network("20.0.0.0/8"),        # Azure
    ipaddress.ip_network("3.0.0.0/8"),         # AWS
    ipaddress.ip_network("157.240.0.0/16")     # Facebook/Meta
]

# Get system IP
def get_system_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return "127.0.0.1"

system_ip = get_system_ip()

# Siren control
siren_playing = False
def play_siren():
    global siren_playing
    if siren_playing:
        return
    try:
        siren_playing = True
        pygame.mixer.init()
        pygame.mixer.music.load(r"C:\Users\HP\Desktop\IDS\siren.mp3")  # Update path if needed
        pygame.mixer.music.play(-1)
    except Exception as e:
        print(f"[ERROR] Failed to play siren: {e}")

# Graceful shutdown
def signal_handler(sig, frame):
    print("\n[INFO] IDS stopped by user.")
    try:
        pygame.mixer.music.stop()
    except:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Check trusted IPs
def is_trusted_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in trusted_ranges)
    except:
        return False

# Track alerted ports
alerted_ports = {}  # Format: {src_ip: set(ports)}

# Packet analysis
def packet_callback(packet):
    global siren_playing

    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src
        dst_port = tcp_layer.dport
        timestamp = datetime.now()

        if src_ip in {system_ip, ignored_ip}:
            return
        if is_trusted_ip(src_ip):
            return
        if dst_port not in sensitive_ports:
            return

        if src_ip not in alerted_ports:
            alerted_ports[src_ip] = set()

        if dst_port in alerted_ports[src_ip]:
            return

        alerted_ports[src_ip].add(dst_port)
        is_private = ipaddress.ip_address(src_ip).is_private
        net_type = "PRIVATE" if is_private else "PUBLIC"

        geo_info = get_geo_info(src_ip)
        if geo_info:
            location_info = f"{geo_info['city']}, {geo_info['region']}, {geo_info['country']} ({geo_info['org']})"
        else:
            location_info = "Location unavailable"

        alert = f"[{timestamp}] ALERT ({net_type}): Suspicious Scan Attempt from {src_ip} ({location_info}) on port {dst_port}"
        print(Fore.RED + alert + Style.RESET_ALL)

        with open(alert_log, "a") as f:
            f.write(alert + "\n")

        send_email_alert(
            subject="🚨 IDS Alert: Suspicious activity",
            message=alert
        )

        threading.Thread(target=play_siren, daemon=True).start()

# === START IDS ===
if __name__ == "__main__":
    print("✅ IDS Running... Monitoring TCP traffic.")
    print("Press CTRL+C to stop.\n")

    # Run enum_detector module (web enum sniffing) in background
    threading.Thread(target=enum_detector.start_sniffing, daemon=True).start()

    try:
        sniff(filter="tcp", prn=packet_callback, store=0)
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")
    finally:
        print("[INFO] Exiting IDS.")
        sys.exit(0)
