from scapy.all import sniff, TCP, Raw, IP
from datetime import datetime
import threading
import ipaddress
from geoip_lookup import get_geo_info
from email_alert import send_email_alert
from colorama import Fore, Style
import pygame
import time

# === Basic Settings ===
ignored_ip = "192.168.18.139"
system_ip = "192.168.18.139"
alert_log = "http_enum_alerts.txt"
siren_playing = False

# Suspicious paths commonly used in enumeration
suspicious_paths = ["/admin", "/backup", "/login", "/.git", "/config", "/.env", "/wp-admin"]

# User-Agents considered safe (legit browsers)
ignored_user_agents = ["Mozilla", "Chrome", "Safari", "Firefox", "Edge"]

# Track per-IP access frequency
recent_requests = {}

def play_siren():
    global siren_playing
    if siren_playing:
        return
    try:
        siren_playing = True
        pygame.mixer.init()
        pygame.mixer.music.load(r"C:\Users\HP\Desktop\IDS\siren.mp3")
        pygame.mixer.music.play(-1)
    except Exception as e:
        print(f"[ERROR] Siren play failed: {e}")

def is_rate_attack(src_ip):
    now = time.time()
    if src_ip not in recent_requests:
        recent_requests[src_ip] = [now]
        return False
    recent_requests[src_ip] = [t for t in recent_requests[src_ip] if now - t < 5]
    recent_requests[src_ip].append(now)
    return len(recent_requests[src_ip]) > 3

def is_legit_browser(http_data):
    for agent in ignored_user_agents:
        if agent in http_data:
            return True
    return False

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        raw_data = packet[Raw].load

        src_ip = ip_layer.src
        dst_port = tcp_layer.dport

        if src_ip in {ignored_ip, system_ip} or dst_port != 80:
            return

        try:
            http_request = raw_data.decode(errors='ignore')
            if http_request.startswith("GET"):
                if is_legit_browser(http_request):
                    return  # Likely manual browser access

                for path in suspicious_paths:
                    if path in http_request:
                        if not is_rate_attack(src_ip):
                            return  # Not enough frequency to consider malicious

                        timestamp = datetime.now()
                        geo_info = get_geo_info(src_ip)
                        location = f"{geo_info['city']}, {geo_info['country']}" if geo_info else "Unknown"
                        alert = f"[{timestamp}] ENUM DETECTED: {src_ip} requested suspicious path {path} (Location: {location})"

                        print(Fore.YELLOW + alert + Style.RESET_ALL)
                        with open(alert_log, "a") as f:
                            f.write(alert + "\n")

                        send_email_alert(
                            subject="🕵️ Web Enumeration Detected",
                            message=alert
                        )
                        threading.Thread(target=play_siren, daemon=True).start()
                        break  # Avoid duplicate alerts for same packet
        except Exception:
            pass  # Silently skip decode issues

# Entry function to be called from main.py
def start_sniffing():
    print("[+] Web Enumeration Monitor Running (HTTP GET on port 80)...")
    sniff(filter="tcp port 80", prn=packet_callback, store=0)
