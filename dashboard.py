from flask import Flask, render_template, jsonify, request
import subprocess
import threading
import os
import time

app = Flask(__name__)

ids_process = None
enum_process = None
ids_running = False

def run_ids():
    global ids_process
    ids_process = subprocess.Popen(["python", "main_process.py"])

def run_enum():
    global enum_process
    enum_process = subprocess.Popen(["python", "enum_process.py"])

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/start_ids', methods=['POST'])
def start_ids():
    global ids_running
    if not ids_running:
        threading.Thread(target=run_ids).start()
        threading.Thread(target=run_enum).start()
        ids_running = True
    return jsonify({'status': 'IDS started'})

@app.route('/stop_ids', methods=['POST'])
def stop_ids():
    global ids_process, enum_process, ids_running
    if ids_process:
        ids_process.terminate()
    if enum_process:
        enum_process.terminate()
    ids_running = False
    return jsonify({'status': 'IDS stopped'})

@app.route('/logs')
def get_logs():
    logs = []
    if os.path.exists("ids_alerts.txt"):
        with open("ids_alerts.txt") as f:
            for line in f:
                logs.append({"type": "Scan", "text": line.strip()})
    if os.path.exists("http_enum_alerts.txt"):
        with open("http_enum_alerts.txt") as f:
            for line in f:
                logs.append({"type": "Enum", "text": line.strip()})
    logs.reverse()
    return jsonify(logs)

if __name__ == '__main__':
    app.run(debug=True)
