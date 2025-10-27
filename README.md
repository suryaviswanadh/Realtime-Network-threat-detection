# 🛡️ Real-Time Network Threat Detection System

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![ML Powered](https://img.shields.io/badge/ML-Powered-orange)](docs/ML_MODELS.md)

An advanced educational tool for real-time network traffic analysis and threat detection powered by Machine Learning.

![Dashboard Screenshot](screenshots/dashboard.png)

## ✨ Key Features

### 🎯 Core Functionality
- **Real-Time Packet Capture** - Monitor live network traffic
- **ML-Powered Detection** - Uses `scikit-learn` for anomaly detection
- **Automated Response** - Instant blocking of malicious sources via a dynamic firewall
- **Modern GUI** - Intuitive interface with live charts

### 🤖 Machine Learning Model
- **Isolation Forest** - Unsupervised anomaly detection to identify unusual traffic patterns.

### 🔒 Security Features
- DoS/DDoS attack detection (rate-based)
- Port scan identification
- SQL Injection and Directory Traversal detection
- Dynamic firewall rules
- IP reputation scoring (internal)
- Geographic threat tracking (mocked)

### 📊 Advanced Tools
- Interactive packet analyzer
- Port scanner with service detection
- Threat intelligence dashboard
- Bandwidth monitoring
- Protocol-specific analysis (HTTP, DNS)

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Administrator/Root privileges (required for packet capture)
- 4GB RAM minimum (8GB recommended for ML)

### Installation
```bash
# 1. Clone the repository
git clone [https://github.com/yourusername/Realtime-Network-Threat-Detection.git](https://github.com/yourusername/Realtime-Network-Threat-Detection.git)
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
