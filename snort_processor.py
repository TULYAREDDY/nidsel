import os
import re
import json
import time
from datetime import datetime
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
from typing import Dict, List, Optional, Tuple
from attack_simulator import AttackSimulator, generate_snort_alert
import random

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SnortAlert:
    def __init__(self, raw_alert: str):
        self.raw_alert = raw_alert
        self.timestamp = None
        self.alert_type = None
        self.priority = None
        self.protocol = None
        self.source_ip = None
        self.source_port = None
        self.dest_ip = None
        self.dest_port = None
        self.classification = None
        self.parse_alert()

    def parse_alert(self) -> None:
        """Parse a Snort alert into structured data"""
        try:
            # Extract timestamp
            timestamp_match = re.search(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)', self.raw_alert)
            if timestamp_match:
                self.timestamp = timestamp_match.group(1)

            # Extract alert type
            alert_match = re.search(r'\[(.*?)\]', self.raw_alert)
            if alert_match:
                self.alert_type = alert_match.group(1)

            # Extract priority
            priority_match = re.search(r'\[Priority: (\d+)\]', self.raw_alert)
            if priority_match:
                self.priority = int(priority_match.group(1))

            # Extract protocol
            protocol_match = re.search(r'(TCP|UDP|ICMP)', self.raw_alert)
            if protocol_match:
                self.protocol = protocol_match.group(1)

            # Extract IP addresses and ports
            ip_port_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+) -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', self.raw_alert)
            if ip_port_match:
                self.source_ip = ip_port_match.group(1)
                self.source_port = int(ip_port_match.group(2))
                self.dest_ip = ip_port_match.group(3)
                self.dest_port = int(ip_port_match.group(4))

            # Determine classification based on alert type and priority
            self.classification = self._determine_classification()

        except Exception as e:
            logger.error(f"Error parsing alert: {e}")

    def _determine_classification(self) -> str:
        """Determine if the alert is malicious, suspicious, or normal"""
        if not self.alert_type or not self.priority:
            return "normal"

        # Keywords indicating malicious activity
        malicious_keywords = [
            "SQL Injection", "EXPLOIT", "MALWARE", "ATTACK", "SCAN",
            "SHELLCODE", "VIRUS", "TROJAN", "BACKDOOR", "RAT"
        ]

        # Check for malicious keywords
        if any(keyword.lower() in self.alert_type.lower() for keyword in malicious_keywords):
            return "malicious"
        
        # Check priority level
        if self.priority == 1:
            return "malicious"
        elif self.priority == 2:
            return "suspicious"
        
        return "normal"

    def to_dict(self) -> Dict:
        """Convert alert to dictionary format for JSON serialization"""
        return {
            "timestamp": self.timestamp,
            "type": self.classification,
            "alert_type": self.alert_type,
            "priority": self.priority,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "raw_alert": self.raw_alert
        }

class SnortAlertHandler(FileSystemEventHandler):
    def __init__(self, callback=None):
        self.callback = callback
        self.last_position = 0
        self.alert_file = "C:\\Snort\\log\\alert.txt"
        self.simulator = AttackSimulator()
        
        # Create alert file if it doesn't exist
        if not os.path.exists(self.alert_file):
            os.makedirs(os.path.dirname(self.alert_file), exist_ok=True)
            with open(self.alert_file, 'w') as f:
                pass

    def on_modified(self, event):
        if event.src_path == self.alert_file:
            self.process_new_alerts()

    def process_new_alerts(self):
        try:
            with open(self.alert_file, 'r') as f:
                f.seek(self.last_position)
                new_content = f.read()
                self.last_position = f.tell()
                
                if new_content and self.callback:
                    self.callback(new_content)
        except Exception as e:
            logger.error(f"Error processing alerts: {e}")

    def start_simulation(self, attack_type, duration=30):
        """Start simulating a specific type of attack"""
        self.simulator.start_attack(attack_type, duration)
        
        # Generate alerts for the attack
        for _ in range(5):
            alert = generate_snort_alert(
                attack_type,
                f"192.168.1.{random.randint(2,254)}",
                "10.0.0.1"
            )
            with open(self.alert_file, 'a') as f:
                f.write(alert + "\n\n")
            time.sleep(1)

class SnortProcessor:
    def __init__(self, alert_callback=None):
        self.alert_handler = SnortAlertHandler(alert_callback)
        self.observer = Observer()
        self.observer.schedule(
            self.alert_handler,
            path=os.path.dirname(self.alert_handler.alert_file),
            recursive=False
        )

    def start(self):
        """Start monitoring Snort alerts"""
        self.observer.start()
        logger.info("Started monitoring Snort alerts")

    def stop(self):
        """Stop monitoring Snort alerts"""
        self.observer.stop()
        self.observer.join()
        logger.info("Stopped monitoring Snort alerts")

    def simulate_attack(self, attack_type, duration=30):
        """Simulate a specific type of attack"""
        self.alert_handler.start_simulation(attack_type, duration)

if __name__ == "__main__":
    # Example usage
    def alert_callback(alert):
        print(f"New alert received:\n{alert}")

    processor = SnortProcessor(alert_callback)
    processor.start()

    try:
        while True:
            print("\nSelect attack to simulate:")
            print("1. Port Scan")
            print("2. SQL Injection")
            print("3. DoS Attack")
            print("4. Malware C&C")
            print("5. Exploit Kit")
            print("6. Exit")
            
            choice = input("Enter your choice (1-6): ")
            
            if choice == "6":
                break
                
            attack_types = {
                "1": "port_scan",
                "2": "sql_injection",
                "3": "dos",
                "4": "malware_cnc",
                "5": "exploit_kit"
            }
            
            if choice in attack_types:
                processor.simulate_attack(attack_types[choice])
            else:
                print("Invalid choice!")
                
    except KeyboardInterrupt:
        processor.stop() 