import time
import random

def simulate_port_scan(callback=None, duration=10):
    """Simulate a port scan attack and optionally call a callback with alert data."""
    src_ip = f"192.168.1.{random.randint(2,254)}"
    dst_ip = "10.0.0.1"
    alert = {
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
        "type": "port_scan",
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "classification": "malicious",
        "priority": 1
    }
    if callback:
        callback(alert)
    return alert 