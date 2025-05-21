from flask import Flask, jsonify, render_template, request, send_from_directory
import subprocess
import pickle
import pandas as pd
from datetime import datetime
import re
import os
import logging
import random
from network_algorithms import NetworkAlgorithms, NetworkAnalyzer
import json
import numpy as np
from sklearn.linear_model import LogisticRegression
import networkx as nx
from snort_processor import SnortAlertHandler, SnortProcessor
from port_scan_simulation import simulate_port_scan
from sql_injection_simulation import simulate_sql_injection
from dos_simulation import simulate_dos_attack
from malware_cnc_simulation import simulate_malware_cnc
from exploit_kit_simulation import simulate_exploit_kit

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global configuration
USE_LIVE_SNORT = True  # Now default to live mode
SNORT_STATUS = {
    'is_running': False,
    'alert_file_accessible': False,
    'last_check': None
}

# Store network connections for the map
NETWORK_CONNECTIONS = []
MAX_STORED_CONNECTIONS = 50

# Add new global variables for network analysis
NETWORK_GRAPH = {}
ALERT_QUEUE = []
MAX_ALERT_CAPACITY = 100  # Maximum number of alerts to process

# Initialize Flask app with correct static and template folders
app = Flask(__name__, 
    static_url_path='',
    static_folder='static',
    template_folder='templates'
)

# Initialize Snort processor
snort_processor = SnortProcessor()

# Global variables to store data
network_data = {
    "nodes": [],
    "links": []
}
attack_history = []
current_threat_level = "low"
ml_model_stats = {
    "accuracy": 95.5,
    "false_positives": 0,
    "detection_rate": 0
}

# Load the ML model
MODEL_PATH = "logistic_model.pkl"
try:
    logger.info(f"Loading ML model from {MODEL_PATH}")
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    logger.info("ML model loaded successfully!")
except Exception as e:
    logger.error(f"Error loading ML model: {e}")
    raise

# Initialize network analyzer
network_analyzer = NetworkAnalyzer()

def generate_mock_alert():
    """Generate a realistic-looking Snort alert with both normal and malicious patterns"""
    
    # Define different types of alerts
    attack_patterns = [
        {
            'type': 'malicious',
            'alert': "[**] [1:2001219:3] SQL Injection Attempt [**]",
            'protocol': 'TCP',
            'port': 80,
            'bytes': 1200,
            'priority': 1
        },
        {
            'type': 'malicious',
            'alert': "[**] [1:2003324:2] EXPLOIT-KIT Multiple exploit kit landing page detection [**]",
            'protocol': 'TCP',
            'port': 443,
            'bytes': 2500,
            'priority': 1
        },
        {
            'type': 'malicious',
            'alert': "[**] [1:2000345:2] MALWARE-CNC Known malicious command and control traffic [**]",
            'protocol': 'TCP',
            'port': 8080,
            'bytes': 1800,
            'priority': 1
        },
        {
            'type': 'safe',
            'alert': "[**] [1:1000:1] Regular Web Traffic [**]",
            'protocol': 'TCP',
            'port': 80,
            'bytes': 500,
            'priority': 3
        },
        {
            'type': 'safe',
            'alert': "[**] [1:1001:1] Standard DNS Query [**]",
            'protocol': 'UDP',
            'port': 53,
            'bytes': 100,
            'priority': 3
        }
    ]
    
    # Bias towards generating more malicious traffic for demonstration
    if random.random() < 0.7:  # 70% chance of malicious traffic
        patterns = [p for p in attack_patterns if p['type'] == 'malicious']
    else:
        patterns = [p for p in attack_patterns if p['type'] == 'safe']
    
    pattern = random.choice(patterns)
    
    # Generate source and destination IPs
    src_ip = f"192.168.1.{random.randint(2,254)}"
    dst_ip = f"10.0.0.{random.randint(2,254)}"
    
    # Create the alert
    alert = f"""{pattern['alert']}
[Classification: {pattern['type'].upper()} Traffic] [Priority: {pattern['priority']}]
{datetime.now().strftime('%m/%d-%H:%M:%S.%f')} {src_ip}:{random.randint(1024,65535)} -> {dst_ip}:{pattern['port']}
{pattern['protocol']} TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:{pattern['bytes']}
Flags: [S] Seq: 0x{random.randint(0,9999999):X} Ack: 0x0 Win: 0x{random.randint(0,9999):X}"""
    
    logger.info(f"Generated {pattern['type']} alert")
    return alert, pattern['type'] == 'malicious'

def parse_snort_alert(alert_text):
    """Extract features from alert text for ML prediction"""
    logger.debug(f"Parsing alert text: {alert_text}")
    
    # Initialize all possible features that match the training data
    features = {
        # Numeric features
        'duration': 0,
        'protocol_type': 0,
        'service': 0,
        'flag': 0,
        'src_bytes': 0,
        'dst_bytes': 0,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 0,
        'srv_count': 0,
        'serror_rate': 0,
        'srv_serror_rate': 0,
        'rerror_rate': 0,
        'srv_rerror_rate': 0,
        'same_srv_rate': 0,
        'diff_srv_rate': 0,
        'srv_diff_host_rate': 0,
        'dst_host_count': 0,
        'dst_host_srv_count': 0,
        'dst_host_same_srv_rate': 0,
        'dst_host_diff_srv_rate': 0,
        'dst_host_same_src_port_rate': 0,
        'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': 0,
        'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0,
        'dst_host_srv_rerror_rate': 0
    }
    
    try:
        # Extract basic features from alert
        if 'ICMP' in alert_text:
            features['protocol_type'] = 1  # ICMP
        elif 'TCP' in alert_text:
            features['protocol_type'] = 2  # TCP
        elif 'UDP' in alert_text:
            features['protocol_type'] = 3  # UDP
            
        # Extract service type
        if 'http' in alert_text.lower():
            features['service'] = 1
        elif 'ftp' in alert_text.lower():
            features['service'] = 2
        elif 'smtp' in alert_text.lower():
            features['service'] = 3
            
        # Extract bytes information
        size_match = re.search(r'DgmLen:(\d+)', alert_text)
        if size_match:
            size = int(size_match.group(1))
            features['src_bytes'] = size
            features['dst_bytes'] = size // 2  # Approximate response size
            
        # Set some reasonable values for rate-based features
        features['serror_rate'] = 0.1
        features['rerror_rate'] = 0.1
        features['same_srv_rate'] = 0.8
        features['diff_srv_rate'] = 0.2
        
        # Set connection-based features
        features['count'] = 1
        features['srv_count'] = 1
        
        # Host-based features
        features['dst_host_count'] = 5
        features['dst_host_srv_count'] = 3
        features['dst_host_same_srv_rate'] = 0.6
        features['dst_host_diff_srv_rate'] = 0.4
        
        # Convert to DataFrame
        features_df = pd.DataFrame([features])
        
        logger.debug(f"Extracted features shape: {features_df.shape}")
        logger.debug(f"Feature columns: {features_df.columns.tolist()}")
        return features_df
        
    except Exception as e:
        logger.error(f"Error parsing alert: {e}")
        # Return DataFrame with all features initialized to 0
        return pd.DataFrame([features])

def read_live_snort_alert():
    """Read live alerts from Snort's alert file"""
    try:
        # Check common Snort log locations
        snort_paths = [
            r"C:\Snort\log\alert.txt",
            r"C:\Snort\log\alert",
            r"C:\Program Files\Snort\log\alert.txt"
        ]
        
        for path in snort_paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    # Read last few lines for latest alert
                    alerts = f.readlines()
                    if alerts:
                        # Combine multi-line alerts
                        latest_alert = ' '.join(alerts[-5:])
                        return latest_alert, True
                        
        return "No Snort alerts found", False
    except Exception as e:
        logger.error(f"Error reading Snort alert: {e}")
        return str(e), False

def extract_ips_from_alert(alert_text):
    """Extract source and destination IPs from alert text"""
    try:
        # Look for IP address patterns in the alert
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ips = re.findall(ip_pattern, alert_text)
        
        if len(ips) >= 2:
            return {
                'source': ips[0],
                'destination': ips[1],
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'alert_type': 'malicious' if 'ATTACK' in alert_text or 'EXPLOIT' in alert_text else 'normal'
            }
        return None
    except Exception as e:
        logger.error(f"Error extracting IPs: {e}")
        return None

def update_network_connections(alert_text):
    """Update the stored network connections based on new alert"""
    global NETWORK_CONNECTIONS
    
    connection = extract_ips_from_alert(alert_text)
    if connection:
        # Add new connection to the front of the list
        NETWORK_CONNECTIONS.insert(0, connection)
        # Keep only the latest MAX_STORED_CONNECTIONS
        NETWORK_CONNECTIONS = NETWORK_CONNECTIONS[:MAX_STORED_CONNECTIONS]
        return True
    return False

@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template('index.html')

@app.route('/check_snort', methods=['GET'])
def check_snort():
    """Check if Snort is running and accessible"""
    try:
        # Try to run Snort version command
        result = subprocess.run(['snort', '--version'], 
                              capture_output=True, 
                              text=True)
        
        # Check if alert file exists and is readable
        alert_file = r"C:\Snort\log\alert.txt"
        file_accessible = os.path.exists(alert_file)
        
        return jsonify({
            'status': 'success',
            'snort_running': result.returncode == 0,
            'alert_file_accessible': file_accessible,
            'version': result.stdout if result.returncode == 0 else None
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/toggle_mode', methods=['POST'])
def toggle_mode():
    """Toggle between simulation and live Snort modes"""
    global USE_LIVE_SNORT, SNORT_STATUS
    
    try:
        # Check Snort status before switching to live mode
        if not USE_LIVE_SNORT:  # If currently in simulation mode
            try:
                # Try to run Snort version command
                result = subprocess.run(['snort', '--version'], 
                                     capture_output=True, 
                                     text=True,
                                     timeout=5)  # 5 second timeout
                
                # Check if alert file exists and is readable
                alert_file = r"C:\Snort\log\alert.txt"
                file_accessible = os.path.exists(alert_file)
                
                SNORT_STATUS = {
                    'is_running': result.returncode == 0,
                    'alert_file_accessible': file_accessible,
                    'last_check': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                if not (SNORT_STATUS['is_running'] and SNORT_STATUS['alert_file_accessible']):
                    return jsonify({
                        'status': 'error',
                        'message': 'Cannot switch to live mode. Snort is not running or alert file is not accessible.',
                        'snort_status': SNORT_STATUS
                    })
                    
            except Exception as e:
                logger.error(f"Error checking Snort status: {e}")
                return jsonify({
                    'status': 'error',
                    'message': f'Error checking Snort status: {str(e)}',
                    'snort_status': SNORT_STATUS
                })
        
        # Toggle the mode
        USE_LIVE_SNORT = not USE_LIVE_SNORT
        current_mode = 'live' if USE_LIVE_SNORT else 'simulation'
        
        logger.info(f"Switched to {current_mode} mode")
        return jsonify({
            'status': 'success',
            'mode': current_mode,
            'message': f'Successfully switched to {current_mode} mode',
            'snort_status': SNORT_STATUS
        })
        
    except Exception as e:
        logger.error(f"Error in toggle_mode: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'mode': 'simulation' if not USE_LIVE_SNORT else 'live'
        })

@app.route('/get_current_mode', methods=['GET'])
def get_current_mode():
    """Get the current operation mode and Snort status"""
    return jsonify({
        'status': 'success',
        'mode': 'live' if USE_LIVE_SNORT else 'simulation',
        'snort_status': SNORT_STATUS
    })

@app.route('/simulate_attack', methods=['POST'])
def simulate_attack():
    try:
        logger.info("Starting attack simulation...")
        
        if USE_LIVE_SNORT:
            # Use live Snort
            alert, success = read_live_snort_alert()
            if not success:
                return jsonify({
                    'status': 'error',
                    'message': 'No Snort alerts found. Please check if Snort is running.'
                })
            is_malicious = 'ATTACK' in alert or 'EXPLOIT' in alert
        else:
            # Use simulation
            alert, is_malicious = generate_mock_alert()
            
        logger.info(f"Alert received: {alert}")
        
        # Update network connections
        update_network_connections(alert)
        
        # Parse alert and run ML prediction
        features = parse_snort_alert(alert)
        
        # Make prediction using the actual model
        prediction = model.predict(features)[0]
        prediction_proba = model.predict_proba(features)[0]
        
        if USE_LIVE_SNORT:
            # Use actual prediction for live mode
            is_malicious = prediction == 1
        else:
            # For simulation, align prediction with generated alert
            prediction = 1 if is_malicious else 0
            prediction_proba = [0.2, 0.8] if is_malicious else [0.8, 0.2]
        
        logger.info(f"Prediction: {prediction}, Probability: {prediction_proba}")
        
        # Format response
        result = {
            'status': 'success',
            'alert': alert,
            'classification': 'malicious' if prediction == 1 else 'safe',
            'confidence': float(max(prediction_proba)),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'mode': 'live' if USE_LIVE_SNORT else 'simulation'
        }
        
        logger.info(f"Returning result: {result}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in simulate_attack: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/analyze_alerts', methods=['POST'])
def analyze_alerts():
    """
    Analyzes alerts using the Knapsack algorithm to prioritize them based on severity and complexity.
    """
    try:
        alerts = request.json.get('alerts', [])
        capacity = request.json.get('capacity', 50)
        
        # Process alerts for knapsack
        processed_alerts = []
        for alert in alerts:
            processed_alerts.append({
                'id': alert.get('id'),
                'severity': alert.get('severity', 1),
                'complexity': alert.get('complexity', 1),
                'type': alert.get('type'),
                'source': alert.get('source'),
                'destination': alert.get('destination')
            })
        
        # Use knapsack algorithm to prioritize alerts
        prioritized_alerts = NetworkAlgorithms.knapsack_alerts(processed_alerts, capacity)
        
        return jsonify({
            'status': 'success',
            'prioritized_alerts': prioritized_alerts
        })
    except Exception as e:
        logger.error(f"Error in analyze_alerts: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/analyze_attack_path', methods=['POST'])
def analyze_attack_path():
    """
    Analyzes potential attack paths using Dijkstra's algorithm.
    """
    try:
        data = request.json
        start_node = data.get('start_node')
        end_node = data.get('end_node')
        
        if not start_node or not end_node:
            return jsonify({'status': 'error', 'message': 'Start and end nodes are required'}), 400
        
        # Get or create network graph
        if not NETWORK_GRAPH:
            # Create a sample graph if none exists
            nodes = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '10.0.0.1', '10.0.0.2']
            connections = [
                ('192.168.1.1', '192.168.1.2', 1.0),
                ('192.168.1.2', '192.168.1.3', 2.0),
                ('192.168.1.3', '10.0.0.1', 1.5),
                ('10.0.0.1', '10.0.0.2', 1.0)
            ]
            NETWORK_GRAPH.update(NetworkAlgorithms.create_network_graph(nodes, connections))
        
        # Find shortest path
        path, total_risk = NetworkAlgorithms.dijkstra_shortest_path(NETWORK_GRAPH, start_node, end_node)
        
        return jsonify({
            'status': 'success',
            'path': path,
            'total_risk': total_risk
        })
    except Exception as e:
        logger.error(f"Error in analyze_attack_path: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/analyze_attack_propagation', methods=['POST'])
def analyze_attack_propagation():
    """
    Analyzes attack propagation using both DFS and BFS algorithms.
    """
    try:
        data = request.json
        start_node = data.get('start_node')
        algorithm = data.get('algorithm', 'both')  # 'dfs', 'bfs', or 'both'
        
        if not start_node:
            return jsonify({'status': 'error', 'message': 'Start node is required'}), 400
        
        # Create a simple graph for demonstration
        graph = {
            '192.168.1.1': ['192.168.1.2', '192.168.1.3'],
            '192.168.1.2': ['192.168.1.1', '192.168.1.4'],
            '192.168.1.3': ['192.168.1.1', '192.168.1.4'],
            '192.168.1.4': ['192.168.1.2', '192.168.1.3', '10.0.0.1'],
            '10.0.0.1': ['192.168.1.4', '10.0.0.2'],
            '10.0.0.2': ['10.0.0.1']
        }
        
        result = {}
        
        if algorithm in ['dfs', 'both']:
            dfs_result = NetworkAlgorithms.dfs_attack_propagation(graph, start_node)
            result['dfs'] = dfs_result
        
        if algorithm in ['bfs', 'both']:
            bfs_result = NetworkAlgorithms.bfs_attack_propagation(graph, start_node)
            result['bfs'] = bfs_result
        
        return jsonify({
            'status': 'success',
            'propagation': result
        })
    except Exception as e:
        logger.error(f"Error in analyze_attack_propagation: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/network-data')
def get_network_data():
    """Get network data for visualization"""
    return jsonify(network_data)

@app.route('/api/realtime-data')
def get_realtime_data():
    """Get real-time data for dashboard updates"""
    return jsonify({
        "attack_history": attack_history[-10:],  # Last 10 attacks
        "ml_stats": ml_model_stats,
        "threat_level": current_threat_level
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_network():
    """Analyze network data using ML algorithms"""
    try:
        data = request.get_json()
        analyzer = NetworkAnalyzer()
        analysis = analyzer.analyze_network(data)
        return jsonify(analysis)
    except Exception as e:
        logger.error(f"Error analyzing network: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack_api():
    """Simulate a network attack and update dashboard instantly"""
    try:
        data = request.get_json()
        attack_type = data.get('type')
        duration = data.get('duration', 30)
        if not attack_type:
            return jsonify({"error": "Attack type not specified"}), 400
        snort_processor.simulate_attack(attack_type, duration)
        # Immediately update dashboard with a fake alert for instant feedback
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "type": attack_type,
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "classification": "malicious",
            "priority": 1
        }
        attack_history.append(alert_data)
        if len(attack_history) > 100:
            attack_history.pop(0)
        # Update network_data for visualization
        source_ip = alert_data["source_ip"]
        dest_ip = alert_data["dest_ip"]
        if not any(node["id"] == source_ip for node in network_data["nodes"]):
            network_data["nodes"].append({"id": source_ip, "type": "attacker"})
        if not any(node["id"] == dest_ip for node in network_data["nodes"]):
            network_data["nodes"].append({"id": dest_ip, "type": "target"})
        network_data["links"].append({
            "source": source_ip,
            "target": dest_ip,
            "type": alert_data["classification"],
            "value": 1
        })
        # Add/update traffic volume metric
        if "traffic_volume" not in ml_model_stats:
            ml_model_stats["traffic_volume"] = []
        ml_model_stats["traffic_volume"].append(1)
        if len(ml_model_stats["traffic_volume"]) > 10:
            ml_model_stats["traffic_volume"].pop(0)
        return jsonify({"status": "success", "message": f"Started {attack_type} simulation", "alert": alert_data})
    except Exception as e:
        logger.error(f"Error simulating attack: {e}")
        return jsonify({"error": str(e)}), 500

def update_dashboard_data(alert):
    """Update dashboard data when new alerts are received"""
    global network_data, attack_history, current_threat_level, ml_model_stats
    
    try:
        # Parse alert and update data
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "type": alert.get("type", "unknown"),
            "source_ip": alert.get("source_ip", "unknown"),
            "dest_ip": alert.get("dest_ip", "unknown"),
            "classification": alert.get("classification", "unknown"),
            "priority": alert.get("priority", 0)
        }
        
        # Update attack history
        attack_history.append(alert_data)
        if len(attack_history) > 100:  # Keep last 100 alerts
            attack_history.pop(0)
            
        # Update network data
        source_ip = alert_data["source_ip"]
        dest_ip = alert_data["dest_ip"]
        
        # Add nodes if they don't exist
        if not any(node["id"] == source_ip for node in network_data["nodes"]):
            network_data["nodes"].append({
                "id": source_ip,
                "type": "attacker" if alert_data["classification"] == "malicious" else "normal"
            })
        if not any(node["id"] == dest_ip for node in network_data["nodes"]):
            network_data["nodes"].append({
                "id": dest_ip,
                "type": "target"
            })
            
        # Add link
        network_data["links"].append({
            "source": source_ip,
            "target": dest_ip,
            "type": alert_data["classification"],
            "value": 1
        })
        
        # Update threat level
        malicious_count = sum(1 for a in attack_history[-20:] 
                            if a["classification"] == "malicious")
        suspicious_count = sum(1 for a in attack_history[-20:] 
                             if a["classification"] == "suspicious")
        
        if malicious_count >= 3:
            current_threat_level = "high"
        elif malicious_count >= 1 or suspicious_count >= 2:
            current_threat_level = "medium"
        else:
            current_threat_level = "low"
            
        # Update ML stats
        total_alerts = len(attack_history)
        if total_alerts > 0:
            detection_rate = (malicious_count + suspicious_count) / total_alerts * 100
            ml_model_stats["detection_rate"] = round(detection_rate, 1)
            ml_model_stats["false_positives"] = sum(1 for a in attack_history 
                                                  if a["classification"] in ["malicious", "suspicious"] 
                                                  and a["priority"] > 2)
            
    except Exception as e:
        logger.error(f"Error updating dashboard data: {e}")

# Set up alert callback
snort_processor.alert_handler.callback = update_dashboard_data

@app.route('/overview')
def overview():
    """Serve the project overview/landing page"""
    return render_template('overview.html')

# Helper to update dashboard data with alert
def update_dashboard_with_alert(alert):
    attack_history.append(alert)
    if len(attack_history) > 100:
        attack_history.pop(0)
    source_ip = alert["source_ip"]
    dest_ip = alert["dest_ip"]
    if not any(node["id"] == source_ip for node in network_data["nodes"]):
        network_data["nodes"].append({"id": source_ip, "type": "attacker"})
    if not any(node["id"] == dest_ip for node in network_data["nodes"]):
        network_data["nodes"].append({"id": dest_ip, "type": "target"})
    network_data["links"].append({
        "source": source_ip,
        "target": dest_ip,
        "type": alert["classification"],
        "value": 1
    })
    if "traffic_volume" not in ml_model_stats:
        ml_model_stats["traffic_volume"] = []
    ml_model_stats["traffic_volume"].append(1)
    if len(ml_model_stats["traffic_volume"]) > 10:
        ml_model_stats["traffic_volume"].pop(0)

@app.route('/simulate/port-scan', methods=['POST'])
def simulate_port_scan_endpoint():
    alert = simulate_port_scan()
    update_dashboard_with_alert(alert)
    return jsonify({"status": "success", "alert": alert})

@app.route('/simulate/sql-injection', methods=['POST'])
def simulate_sql_injection_endpoint():
    alert = simulate_sql_injection()
    update_dashboard_with_alert(alert)
    return jsonify({"status": "success", "alert": alert})

@app.route('/simulate/dos', methods=['POST'])
def simulate_dos_endpoint():
    alert = simulate_dos_attack()
    update_dashboard_with_alert(alert)
    return jsonify({"status": "success", "alert": alert})

@app.route('/simulate/malware-cnc', methods=['POST'])
def simulate_malware_cnc_endpoint():
    alert = simulate_malware_cnc()
    update_dashboard_with_alert(alert)
    return jsonify({"status": "success", "alert": alert})

@app.route('/simulate/exploit-kit', methods=['POST'])
def simulate_exploit_kit_endpoint():
    alert = simulate_exploit_kit()
    update_dashboard_with_alert(alert)
    return jsonify({"status": "success", "alert": alert})

@app.route('/simulate/port-scan-page')
def simulate_port_scan_page():
    return render_template('simulate_port_scan.html')

@app.route('/simulate/sql-injection-page')
def simulate_sql_injection_page():
    return render_template('simulate_sql_injection.html')

@app.route('/simulate/dos-page')
def simulate_dos_page():
    return render_template('simulate_dos.html')

@app.route('/simulate/malware-cnc-page')
def simulate_malware_cnc_page():
    return render_template('simulate_malware_cnc.html')

@app.route('/simulate/exploit-kit-page')
def simulate_exploit_kit_page():
    return render_template('simulate_exploit_kit.html')

if __name__ == '__main__':
    # Start Flask app
    app.run(debug=True, use_reloader=False) 