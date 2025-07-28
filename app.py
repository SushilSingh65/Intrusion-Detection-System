from flask import Flask, render_template, request, jsonify
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
import threading
import ipaddress
import pygame
import time

from geoip_lookup import get_geo_info
from email_alert import send_email_alert
import enum_detector  # Web enum detector module

app = Flask(__name__)

# === Runtime State ===
running = False
muted = False
alert_count = 0
alerts = []
ip_table = {}
ids_thread = None
stop_sniffing_flag = threading.Event()

# === Settings ===
ignored_ips = {"192.168.18.139", "192.168.18.5", "192.168.153.84", "192.168.28.84", "192.168.18.19"}
sensitive_ports = {21, 22, 23, 80, 443, 445, 3306, 3389, 8080, 9090, 5000}
alert_log = "ids_alerts.txt"
siren_path = r"C:\Users\HP\Desktop\IDS\siren.mp3"

# === Siren ===
def play_siren():
    global muted
    if muted: return
    try:
        pygame.mixer.init()
        pygame.mixer.music.load(siren_path)
        pygame.mixer.music.play(-1)
    except Exception as e:
        print(f"[ERROR] Siren failed: {e}")

def stop_siren():
    try:
        pygame.mixer.music.stop()
    except:
        pass

# === IDS Packet Handling ===
def handle_packet(packet):
    global alert_count

    if stop_sniffing_flag.is_set():
        return

    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_port = tcp_layer.dport

        if src_ip in ignored_ips:
            return
        if dst_port not in sensitive_ports:
            return

        if src_ip not in ip_table:
            geo = get_geo_info(src_ip) or {}
            ip_table[src_ip] = {
                "type": "PRIVATE" if ipaddress.ip_address(src_ip).is_private else "PUBLIC",
                "location": f"{geo.get('city', '')}, {geo.get('region', '')}, {geo.get('country', '')}",
                "count": 1
            }
        else:
            ip_table[src_ip]["count"] += 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] ALERT: {src_ip} -> port {dst_port}"
        print(alert_msg)
        alerts.insert(0, alert_msg)
        alert_count += 1
        if len(alerts) > 100:
            alerts.pop()

        # Log and notify
        with open(alert_log, "a") as f:
            f.write(alert_msg + "\n")
        send_email_alert("🚨 IDS Alert", alert_msg)
        threading.Thread(target=play_siren, daemon=True).start()

# === IDS Sniffing Thread ===
def sniff_packets():
    sniff(filter="tcp", prn=handle_packet, store=0, stop_filter=lambda x: stop_sniffing_flag.is_set())

# === Flask Routes ===
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/start_ids", methods=["POST"])
def start_ids():
    global running, ids_thread, stop_sniffing_flag
    if not running:
        running = True
        stop_sniffing_flag.clear()
        ids_thread = threading.Thread(target=sniff_packets, daemon=True)
        ids_thread.start()
        threading.Thread(target=enum_detector.start_sniffing, daemon=True).start()
    return "", 204

@app.route("/stop_ids", methods=["POST"])
def stop_ids():
    global running
    running = False
    stop_sniffing_flag.set()
    stop_siren()
    return "", 204

@app.route("/mute", methods=["POST"])
def mute():
    global muted
    muted = True
    stop_siren()
    return "", 204

@app.route("/unmute", methods=["POST"])
def unmute():
    global muted
    muted = False
    return "", 204

@app.route("/status")
def status():
    return jsonify({
        "running": running,
        "muted": muted,
        "alert_count": alert_count,
        "alerts": alerts,
        "ip_table": ip_table
    })

if __name__ == "__main__":
    app.run(debug=True)
