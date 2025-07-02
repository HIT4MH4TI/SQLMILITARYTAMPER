# main.py (Produksi Militer dan Intelijen)
import time
import logging
import threading
from datetime import datetime

from flask import Flask, jsonify, request
import mysql.connector
from mysql.connector import Error

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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(module)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/military_tamper/main.log"),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

latest_alerts = []
latest_vuln_report = ""
alerts_lock = threading.Lock()
vuln_report_lock = threading.Lock()

@app.route('/alerts', methods=['GET'])
def get_alerts():
    with alerts_lock:
        return jsonify({"alerts": latest_alerts[-100:]})

@app.route('/vulnerability_report', methods=['GET'])
def get_vulnerability_report():
    with vuln_report_lock:
        return jsonify({"report": latest_vuln_report})

@app.route('/command', methods=['POST'])
def receive_command():
    data = request.json
    command = data.get("command")
    logging.info(f"Received command: {command}")
    # Validasi dan proses command sesuai kebijakan keamanan
    return jsonify({"status": "received", "command": command})

def run_api():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, ssl_context=('/etc/ssl/certs/server.crt', '/etc/ssl/private/server.key'))

def main():
    global latest_alerts, latest_vuln_report

    monitored_paths = [
        "/etc/critical_config.conf",
        "/var/log/security.log",
        "/opt/military_app/bin/",
    ]
    hash_store_file = "/var/lib/military_tamper/hash_store.json"

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
