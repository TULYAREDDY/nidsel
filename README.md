# Network Intrusion Detection System (NIDS)

An advanced Network Intrusion Detection System that combines Snort alerts with Machine Learning for enhanced threat detection and visualization.

## Features

- Real-time network traffic monitoring
- Machine Learning-based threat detection
- Interactive dashboard with:
  - Attack distribution visualization
  - Traffic analysis
  - Network map
  - Attack history
  - ML statistics
- Attack simulation capabilities
- Snort alert integration

## Requirements

- Python 3.8+
- Snort (optional, for live monitoring)
- Required Python packages:
  - Flask
  - pandas
  - scikit-learn
  - watchdog
  - scapy
  - requests

## Installation

1. Clone the repository:
```bash
git clone https://github.com/TULYAREDDY/nids.git
cd nids
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. (Optional) Install Snort for live monitoring

## Usage

1. Start the application:
```bash
python snort_ml_bridge.py
```

2. Open your browser and navigate to:
```
http://127.0.0.1:5000
```
3. open
 ```
landing-page/index.html
```

4. Use the dashboard to:
   - Monitor network traffic
   - View attack distributions
   - Analyze network topology
   - Simulate attacks
   - Export data

## Project Structure

- `snort_ml_bridge.py`: Main application file
- `snort_processor.py`: Snort alert processing
- `attack_simulator.py`: Attack simulation module
- `network_algorithms.py`: Network analysis algorithms
- `templates/`: HTML templates
- `static/`: Static files (CSS, JS)

## License

MIT License 
