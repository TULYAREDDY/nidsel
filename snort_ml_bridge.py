from flask import Flask, jsonify, render_template, request
import subprocess
import pickle
import pandas as pd
from datetime import datetime
import re
import os
import logging
import random

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global configuration
USE_LIVE_SNORT = False  # Default to simulation mode
SNORT_STATUS = {
    'is_running': False,
    'alert_file_accessible': False,
    'last_check': None
}

# Store network connections for the map
NETWORK_CONNECTIONS = []
MAX_STORED_CONNECTIONS = 50

app = Flask(__name__)

# Load the ML model from the correct path
MODEL_PATH = r"C:\Users\tulya\el4\EL4\logistic_model.pkl"
try:
    logger.info(f"Loading ML model from {MODEL_PATH}")
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    logger.info("ML model loaded successfully!")
except Exception as e:
    logger.error(f"Error loading ML model: {e}")
    raise

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

@app.route('/network_data')
def get_network_data():
    """Get network connection data for visualization"""
    try:
        # If no connections exist, generate some mock data
        if not NETWORK_CONNECTIONS and not USE_LIVE_SNORT:
            mock_alert, _ = generate_mock_alert()
            update_network_connections(mock_alert)
        
        # Format data for visualization
        nodes = set()
        links = []
        
        for conn in NETWORK_CONNECTIONS:
            nodes.add(conn['source'])
            nodes.add(conn['destination'])
            links.append({
                'source': conn['source'],
                'target': conn['destination'],
                'type': conn['alert_type'],
                'timestamp': conn['timestamp']
            })
        
        nodes = [{'id': ip, 'group': 1} for ip in nodes]
        
        return jsonify({
            'status': 'success',
            'data': {
                'nodes': nodes,
                'links': links
            }
        })
    except Exception as e:
        logger.error(f"Error getting network data: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
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

if __name__ == '__main__':
    app.run(debug=True) 