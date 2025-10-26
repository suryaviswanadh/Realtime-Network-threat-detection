# 🛡️ Real-Time Network Threat Detection System

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![ML Powered](https://img.shields.io/badge/ML-Powered-orange)](docs/ML_MODELS.md)

An advanced educational tool for real-time network traffic analysis and threat detection powered by Machine Learning.

![Dashboard Screenshot](screenshots/dashboard.png)

## ✨ Key Features

### 🎯 Core Functionality
- **Real-Time Packet Capture** - Monitor live network traffic
- **ML-Powered Detection** - 5 AI models for threat identification
- **Automated Response** - Instant blocking of malicious sources
- **Beautiful GUI** - Modern, intuitive interface with live charts

### 🤖 Machine Learning Models
1. **Isolation Forest** - Unsupervised anomaly detection
2. **Deep Neural Network** - Multi-class threat classification
3. **Random Forest** - Fast, interpretable predictions
4. **LSTM** - Sequential pattern recognition
5. **AutoEncoder** - Learns normal traffic baselines

### 🔒 Security Features
- DoS/DDoS attack detection
- Port scan identification
- Malware traffic analysis
- Zero-day threat detection
- Dynamic firewall rules
- IP reputation scoring
- Geographic threat tracking

### 📊 Advanced Tools
- Interactive packet analyzer
- Port scanner with service detection
- Threat intelligence dashboard
- Bandwidth monitoring
- Protocol-specific analysis
- Session recording & playback

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Administrator/Root privileges (required for packet capture)
- 4GB RAM minimum (8GB recommended for ML)

### Installation
```bash
# 1. Clone the repository
git clone https://github.com/yourusername/Realtime-Network-Threat-Detection.git
cd Realtime-Network-Threat-Detection

# 2. Create virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
# Windows (as Administrator)
python main.py

# Linux/Mac (with sudo)
sudo python main.py
```

## 📖 Usage Examples

### Basic Monitoring
```python
1. Enter target IP: 192.168.1.1
2. Click "Start Monitoring"
3. Watch real-time threat detection
4. Review alerts in Security Alerts panel
```

### Advanced Features
```python
# Threat Intelligence
Menu → Advanced → Threat Intelligence
- View IP reputation scores
- Analyze threat patterns
- Export threat reports

# Firewall Management
Menu → Advanced → Firewall Manager
- Create custom rules
- Block/Allow specific IPs
- Monitor rule effectiveness

# ML Anomaly Detection
Menu → Advanced → Anomaly Detection
- View AI-detected anomalies
- Check model confidence scores
- Analyze unusual patterns
```

## 🎓 How It Works

### Detection Pipeline
