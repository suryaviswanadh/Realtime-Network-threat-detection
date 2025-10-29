# 🛡️ Real-Time Network Threat Detection with Machine Learning

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)
![GUI](https://img.shields.io/badge/Interface-Tkinter-orange)

An advanced **real-time Intrusion Detection System (IDS)** built using **Python and Machine Learning**.  
This tool captures live network traffic, analyzes both **packet-level** and **flow-level** data, and detects threats using a **Random Forest classifier** trained on the **CICIDS2017 dataset**.  
It includes an interactive **Tkinter GUI** for live monitoring, analysis, and alert visualization.

---

## 🚀 Key Features

- **🧠 ML-Based Threat Analysis:**  
  Detects anomalies using trained Random Forest models on real traffic data.

- **📡 Real-Time Packet Capture:**  
  Uses **Scapy** for live packet sniffing and protocol-level inspection.

- **⚡ Packet & Flow Detection:**  
  Detects DoS, DDoS, Port Scanning, and Infiltration patterns in real-time.

- **🖥️ Graphical Interface (Tkinter):**  
  - Real-time charts for network activity  
  - Live alerts and statistics  
  - Traffic visualization dashboard  

- **🧰 Tools Integrated:**  
  - Port Scanner  
  - Bandwidth Monitor  
  - IP Firewall Blocker  
  - Packet Analyzer  

- **📊 Dashboards:**  
  - Threat Summary  
  - Protocol Statistics  
  - Real-time Network Utilization  

---

## ⚙️ System Workflow

### 1️⃣ Packet-Level Detection
- Scapy captures packets directly from your network interface.  
- Analyzes IP, TCP, UDP, and ICMP headers.  
- Performs heuristic-based detection (e.g., DoS and port scan detection).  
- Generates alerts in the GUI.

### 2️⃣ Flow-Level Detection
- Packets are grouped into network flows.  
- Extracts 78+ statistical flow features (e.g., duration, packet rate, byte rate).  
- Features normalized via `rf_scaler.joblib`.  
- Random Forest model (`rf_model.joblib`) classifies traffic as **benign** or **attack**.  
- Alerts displayed in real-time on the GUI.

---

## 🧩 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/suryaviswanadh/Realtime-Network-threat-detection.git
cd Realtime-Network-threat-detection
2. Create and Activate Virtual Environment
bash
Copy code
python -m venv .venv
# On Windows
.\.venv\Scripts\Activate.ps1
# On Linux/Mac
source .venv/bin/activate
3. Install Dependencies
bash
Copy code
pip install -r requirements.txt
🧠 Train Your Own Model
To customize your model with new datasets (e.g., CICIDS2017):

Download the dataset from
🔗 Google Drive Dataset Folder

Place CSV files inside the training/ folder.

Run:

bash
Copy code
cd training
python train_random_forest.py
Generated files:

Copy code
rf_model.joblib
rf_scaler.joblib
rf_feature_names.joblib
rf_classes.joblib
These files are automatically loaded by main.py during real-time monitoring.

▶️ How to Run
⚠️ Run as Administrator / Root for network capture access.

bash
Copy code
cd Realtime-Network-threat-detection
.\.venv\Scripts\Activate.ps1
python main.py
Then:

Select network interface or IP to monitor.

Click Start Monitoring.

Watch live alerts, stats, and detection logs update in real time.

📸 Screenshots
🖥️ Main Dashboard
(Add image under screenshots/ folder and reference it below)



📈 Threat Analysis

🧾 Folder Structure
graphql
Copy code
Realtime-Network-threat-detection/
│
├── main.py                     # Main GUI application
├── monitoring/                 # Packet sniffing and detection backend
├── utils/                      # Helper utilities and constants
├── training/                   # ML model training scripts
├── models/                     # Trained model files (.joblib)
├── screenshots/                # GUI images for README
├── requirements.txt            # Dependency list
└── README.md                   # Project documentation
🧪 Example Output
When detecting malicious packets or flows:

css
Copy code
[ALERT] Possible DDoS Attack Detected from 192.168.1.22
[ALERT] Port Scan Activity from 10.0.0.15
[INFO] Normal Traffic - Flow classified as BENIGN
🧰 Requirements.txt (Dependencies)
For convenience, here’s the same list included in your project file:

nginx
Copy code
pandas
numpy
scapy
matplotlib
scikit-learn
joblib
tk
threading
datetime
warnings
(Tkinter is included with Python by default; you only need to install others.)

🤝 Contributing
Contributions, bug reports, and ideas are welcome!
Please open a Pull Request or Issue on GitHub.

🪪 License
This project is licensed under the MIT License — you are free to use and modify it with credit.

💬 Author
👨‍💻 Surya Viswanadh
🔗 GitHub Profile
📧 Reach out for collaboration or ideas!

⭐ If you like this project, don’t forget to star it on GitHub!

yaml
Copy code

---

✅ **Copy everything above** into a file named `README.md`  
and place it inside your repository root folder (`Realtime-Network-threat-detection/`).  

Would you like me to create a **short “Project Description”** (2–3 lines) you can pa
