import time
import logging
import threading
from datetime import datetime
import os
import shutil
import subprocess

from flask import Flask, jsonify, request
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from military_tamper import (
    TamperDetector,
    VulnerabilityAnalyzer,
    AnomalyDetector,
    HardwareSensor,
    monitor_sensors,
    alert_print,
    check_user_credentials,
    list_databases,
    list_tables,
)

# Setup logging produksi
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(module)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/military_tamper/main.log"),
        logging.StreamHandler()
    ]
)

# Prometheus metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP Requests', ['method', 'endpoint', 'http_status'])
REQUEST_LATENCY = Histogram('http_request_latency_seconds', 'HTTP Request latency', ['endpoint'])

app = Flask(__name__)

latest_alerts = []
latest_vuln_report = ""
alerts_lock = threading.Lock()
vuln_report_lock = threading.Lock()

def record_metrics(endpoint, method, status_code, latency):
    REQUEST_COUNT.labels(method=method, endpoint=endpoint, http_status=status_code).inc()
    REQUEST_LATENCY.labels(endpoint=endpoint).observe(latency)

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/alerts', methods=['GET'])
def get_alerts():
    start = time.time()
    with alerts_lock:
        data = jsonify({"alerts": latest_alerts[-100:]})
    latency = time.time() - start
    record_metrics('/alerts', 'GET', 200, latency)
    return data

@app.route('/vulnerability_report', methods=['GET'])
def get_vulnerability_report():
    start = time.time()
    with vuln_report_lock:
        data = jsonify({"report": latest_vuln_report})
    latency = time.time() - start
    record_metrics('/vulnerability_report', 'GET', 200, latency)
    return data

@app.route('/command', methods=['POST'])
def receive_command():
    start = time.time()
    data = request.json
    command = data.get("command")
    logging.info(f"Received command: {command}")
    # TODO: Validasi dan eksekusi command sesuai kebijakan
    latency = time.time() - start
    record_metrics('/command', 'POST', 200, latency)
    return jsonify({"status": "received", "command": command})

def run_api():
    # Jalankan Flask API (TLS dan autentikasi via reverse proxy di produksi)
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def backup_data(source_dir, backup_dir, max_backups=7):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"backup_{timestamp}")
        shutil.copytree(source_dir, backup_path)
        logging.info(f"Backup created at {backup_path}")

        # Hapus backup lama jika lebih dari max_backups
        backups = sorted([d for d in os.listdir(backup_dir) if d.startswith("backup_")])
        while len(backups) > max_backups:
            old_backup = backups.pop(0)
            shutil.rmtree(os.path.join(backup_dir, old_backup))
            logging.info(f"Old backup removed: {old_backup}")
    except Exception as e:
        logging.error(f"Backup failed: {e}")

def main():
    global latest_alerts, latest_vuln_report

    monitored_paths = [
        "/etc/critical_config.conf",
        "/var/log/security.log",
        "/opt/military_app/bin/",
    ]
    hash_store_file = "/var/lib/military_tamper/hash_store.json"
    backup_dir = "/var/backups/military_tamper"

    tamper_detector = TamperDetector(monitored_paths, hash_store_file, alert_callback=alert_print)
    ai_detector = AnomalyDetector(model_path="/opt/models/anomaly_model.h5")

    sensors = [
        HardwareSensor("Sensor-1", sensor_interface=YourRealSensorInterface1()),
        HardwareSensor("Sensor-2", sensor_interface=YourRealSensorInterface2()),
    ]

    vuln_analyzer = VulnerabilityAnalyzer(scan_tool_path="nmap", cvss_db_path="/opt/data/cvss_db.json")
    target_ip = "192.168.1.10"

    db_host = "localhost"
    db_user = "secure_user"
    db_pass = "secure_password"
    db_name = "secure_db"

    tamper_detector.start_monitoring(interval_sec=120)

    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()

    last_backup_time = 0
    backup_interval = 24 * 3600  # backup harian

    try:
        while True:
            monitor_sensors(sensors, alert_print, threshold=75.0)

            sample_data = fetch_real_time_activity_data()
            if ai_detector.predict(sample_data):
                alert_msg = "Anomaly detected by AI!"
                alert_print(alert_msg)
                with alerts_lock:
                    latest_alerts.append(f"{datetime.now()}: {alert_msg}")

            current_minute = datetime.now().minute

            if current_minute % 10 == 0:
                scan_output = vuln_analyzer.run_scan(target_ip)
                if scan_output:
                    vulns = vuln_analyzer.parse_scan_result(scan_output)
                    risk = vuln_analyzer.assess_risk(vulns)
                    report = vuln_analyzer.generate_report(risk)
                    logging.info(report)
                    with vuln_report_lock:
                        latest_vuln_report = report

            username_test = "admin"
            password_test = "StrongPassword123!"
            valid, msg = check_user_credentials(db_host, db_user, db_pass, db_name, username_test, password_test)
            if valid:
                alert_msg = f"Valid login found for user '{username_test}': {msg}"
                alert_print(alert_msg)
                with alerts_lock:
                    latest_alerts.append(f"{datetime.now()}: {alert_msg}")
            else:
                logging.info(f"Login check for user '{username_test}': {msg}")

            if current_minute % 15 == 0:
                dbs = list_databases(db_host, db_user, db_pass)
                alert_print(f"Databases found: {dbs}")
                with alerts_lock:
                    latest_alerts.append(f"{datetime.now()}: Databases found: {dbs}")
                if db_name in dbs:
                    tables = list_tables(db_host, db_user, db_pass, db_name)
                    alert_print(f"Tables in {db_name}: {tables}")
                    with alerts_lock:
                        latest_alerts.append(f"{datetime.now()}: Tables in {db_name}: {tables}")

            # Backup data otomatis harian
            now = time.time()
            if now - last_backup_time > backup_interval:
                backup_data("/var/lib/military_tamper", backup_dir)
                last_backup_time = now

            time.sleep(30)

    except KeyboardInterrupt:
        tamper_detector.stop_monitoring()
        logging.info("System shutdown initiated by user.")

def fetch_real_time_activity_data():
    # Implementasi produksi mengambil data nyata dari sensor dan log
    return []

class YourRealSensorInterface1:
    def read_value(self):
        # Implementasi baca sensor nyata sesuai hardware militer
        raise NotImplementedError("Implement sensor interface sesuai hardware")

class YourRealSensorInterface2:
    def read_value(self):
        # Implementasi baca sensor nyata sesuai hardware militer
        raise NotImplementedError("Implement sensor interface sesuai hardware")

if __name__ == "__main__":
    main()
