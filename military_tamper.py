import os
import time
import json
import logging
import hashlib
import subprocess
from threading import Thread, Event
from datetime import datetime

import mysql.connector
from mysql.connector import Error

# Konfigurasi logging tingkat produksi
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(module)s - %(message)s',
    handlers=[
        logging.FileHandler("military_tamper.log"),
        logging.StreamHandler()
    ]
)

class TamperDetector:
    def __init__(self, monitored_paths, hash_store_path, alert_callback):
        self.monitored_paths = monitored_paths
        self.hash_store_path = hash_store_path
        self.alert_callback = alert_callback
        self.hash_store = {}
        self.stop_event = Event()
        self.monitor_thread = None

    def calculate_hash(self, filepath):
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Hash calculation failed for {filepath}: {e}")
            return None

    def load_hash_store(self):
        if os.path.isfile(self.hash_store_path):
            try:
                with open(self.hash_store_path, 'r') as f:
                    self.hash_store = json.load(f)
                logging.info("Hash store loaded successfully.")
            except Exception as e:
                logging.error(f"Failed to load hash store: {e}")
                self.hash_store = {}
        else:
            logging.info("No existing hash store found; initializing new store.")
            self.hash_store = {}

    def save_hash_store(self):
        try:
            with open(self.hash_store_path, 'w') as f:
                json.dump(self.hash_store, f, indent=2)
            logging.info("Hash store saved successfully.")
        except Exception as e:
            logging.error(f"Failed to save hash store: {e}")

    def scan_files(self):
        tamper_detected = False
        for path in self.monitored_paths:
            if os.path.isfile(path):
                files_to_check = [path]
            elif os.path.isdir(path):
                files_to_check = []
                for root, _, files in os.walk(path):
                    for file in files:
                        files_to_check.append(os.path.join(root, file))
            else:
                logging.warning(f"Monitored path not found: {path}")
                continue

            for file_path in files_to_check:
                current_hash = self.calculate_hash(file_path)
                if current_hash is None:
                    continue
                old_hash = self.hash_store.get(file_path)
                if old_hash is None:
                    self.hash_store[file_path] = current_hash
                    logging.info(f"New file added to monitoring: {file_path}")
                elif old_hash != current_hash:
                    tamper_detected = True
                    message = f"Tampering detected: {file_path}"
                    logging.warning(message)
                    self.alert_callback(message)
                    self.hash_store[file_path] = current_hash
        self.save_hash_store()
        return tamper_detected

    def _monitor_loop(self, interval_sec):
        while not self.stop_event.is_set():
            self.scan_files()
            time.sleep(interval_sec)

    def start_monitoring(self, interval_sec=60):
        self.load_hash_store()
        self.stop_event.clear()
        self.monitor_thread = Thread(target=self._monitor_loop, args=(interval_sec,), daemon=True)
        self.monitor_thread.start()
        logging.info("Tamper monitoring started.")

    def stop_monitoring(self):
        self.stop_event.set()
        if self.monitor_thread:
            self.monitor_thread.join()
        logging.info("Tamper monitoring stopped.")

class VulnerabilityAnalyzer:
    def __init__(self, scan_tool_path="nmap", cvss_db_path=None):
        self.scan_tool_path = scan_tool_path
        self.cvss_db = {}
        if cvss_db_path and os.path.isfile(cvss_db_path):
            self.load_cvss_db(cvss_db_path)
        else:
            logging.warning("CVSS database path invalid or not provided; vulnerability scoring disabled.")

    def load_cvss_db(self, path):
        try:
            with open(path, 'r') as f:
                self.cvss_db = json.load(f)
            logging.info("CVSS database loaded.")
        except Exception as e:
            logging.error(f"Failed to load CVSS DB: {e}")

    def run_scan(self, target_ip):
        try:
            cmd = [self.scan_tool_path, '-sV', '--script', 'vulners', target_ip]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            logging.info(f"Vulnerability scan completed for {target_ip}.")
            return proc.stdout
        except subprocess.TimeoutExpired:
            logging.error("Vulnerability scan timed out.")
            return None
        except Exception as e:
            logging.error(f"Vulnerability scan failed: {e}")
            return None

    def parse_scan_result(self, scan_output):
        vulnerabilities = []
        if not scan_output:
            return vulnerabilities
        for line in scan_output.splitlines():
            if "CVE-" in line:
                parts = line.split()
                cve_id = parts[0]
                cvss_score = self.cvss_db.get(cve_id, {}).get("cvss_score", "N/A")
                vulnerabilities.append({"cve": cve_id, "cvss_score": cvss_score})
        return vulnerabilities

    def assess_risk(self, vulnerabilities):
        high = [v for v in vulnerabilities if v["cvss_score"] != "N/A" and v["cvss_score"] >= 7.0]
        medium = [v for v in vulnerabilities if v["cvss_score"] != "N/A" and 4.0 <= v["cvss_score"] < 7.0]
        low = [v for v in vulnerabilities if v["cvss_score"] != "N/A" and v["cvss_score"] < 4.0]
        logging.info(f"Vulnerability risk assessment: High={len(high)}, Medium={len(medium)}, Low={len(low)}")
        return {"high": high, "medium": medium, "low": low}

    def generate_report(self, risk_assessment):
        report = ["Vulnerability Assessment Report", "==============================="]
        for level in ["high", "medium", "low"]:
            report.append(f"\n{level.capitalize()} Risk Vulnerabilities:")
            for v in risk_assessment[level]:
                report.append(f"- {v['cve']} (CVSS Score: {v['cvss_score']})")
        return "\n".join(report)

class AnomalyDetector:
    def __init__(self, model_path=None):
        # Implementasi produksi harus memuat model AI nyata, misal TensorFlow/Keras model
        self.model_path = model_path
        self.model = self._load_model() if model_path else None

    def _load_model(self):
        import tensorflow as tf
        try:
            model = tf.keras.models.load_model(self.model_path)
            logging.info("AI anomaly detection model loaded.")
            return model
        except Exception as e:
            logging.error(f"Failed to load AI model: {e}")
            return None

    def predict(self, data):
        if self.model is None:
            logging.warning("AI model not loaded; skipping anomaly detection.")
            return False
        import numpy as np
        try:
            data_np = np.array(data)
            preds = self.model.predict(data_np)
            anomaly = preds.max() > 0.5  # Threshold bisa disesuaikan
            if anomaly:
                logging.info("Anomaly detected by AI model.")
            return anomaly
        except Exception as e:
            logging.error(f"AI prediction failed: {e}")
            return False

class HardwareSensor:
    def __init__(self, sensor_id, sensor_interface):
        self.sensor_id = sensor_id
        self.sensor_interface = sensor_interface  # Interface untuk sensor fisik

    def read(self):
        try:
            value = self.sensor_interface.read_value()
            logging.debug(f"Sensor {self.sensor_id} read value: {value}")
            return value
        except Exception as e:
            logging.error(f"Sensor {self.sensor_id} read failed: {e}")
            return None

def monitor_sensors(sensors, alert_callback, threshold=75.0):
    for sensor in sensors:
        value = sensor.read()
        if value is not None and value > threshold:
            message = f"Sensor {sensor.sensor_id} anomaly detected: {value}"
            logging.warning(message)
            alert_callback(message)

def alert_print(message):
    print(f"[ALERT] {datetime.now()} - {message}")
    logging.info(f"Alert: {message}")

# Database audit functions with secure connection and error handling

def check_user_credentials(host, user, passwd, database, username_input, password_input):
    try:
        connection = mysql.connector.connect(host=host, user=user, password=passwd, database=database)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT Password FROM users WHERE Username = %s"
        cursor.execute(query, (username_input,))
        result = cursor.fetchone()
        if result:
            # Password harus disimpan hashed di produksi; contoh verifikasi bcrypt:
            import bcrypt
            stored_hash = result['Password'].encode('utf-8')
            if bcrypt.checkpw(password_input.encode('utf-8'), stored_hash):
                return True, "Login successful"
            else:
                return False, "Incorrect password"
        else:
            return False, "Username not found"
    except Error as e:
        logging.error(f"Database error: {e}")
        return False, f"Database error: {e}"
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals() and connection.is_connected():
            connection.close()

def list_databases(host, user, passwd):
    try:
        connection = mysql.connector.connect(host=host, user=user, password=passwd)
        cursor = connection.cursor()
        cursor.execute("SHOW DATABASES")
        dbs = [db[0] for db in cursor.fetchall()]
        return dbs
    except Error as e:
        logging.error(f"Database error: {e}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals() and connection.is_connected():
            connection.close()

def list_tables(host, user, passwd, database):
    try:
        connection = mysql.connector.connect(host=host, user=user, password=passwd, database=database)
        cursor = connection.cursor()
        cursor.execute("SHOW TABLES")
        tables = [table[0] for table in cursor.fetchall()]
        return tables
    except Error as e:
        logging.error(f"Database error: {e}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals() and connection.is_connected():
            connection.close()
