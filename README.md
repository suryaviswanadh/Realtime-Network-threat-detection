
# Real-Time Network Threat Detection with ML & Flow Analysis

This is an advanced real-time network intrusion detection system (IDS) built with Python. It captures live network traffic, performs both packet-level and flow-level analysis, and uses a pre-trained Random Forest model to classify network flows and detect threats.

The application features a complete multi-threaded Tkinter GUI for real-time statistics, live alerts, and access to network tools.

![Main Dashboard](screenshots/dashboard.png)
*(You should add a new screenshot of your main GUI to the `screenshots` folder)*

## Key Features

* **Real-Time Packet Capture:** Uses Scapy to capture live network packets from your network interface.
* **Flow-Based Threat Detection (Primary Method):**
    * Assembles individual packets into network "flows" (conversations between two endpoints).
    * Calculates 78+ features for each flow when it terminates (e.g., `Flow Duration`, `Fwd Packet Length Mean`, `Flow IAT Max`, etc.), mirroring the CIC-IDS dataset.
    * Uses a pre-trained **Random Forest Classifier** (`rf_model.joblib`) to classify each flow as `BENIGN` or a specific attack type (e.g., `FTP-Patator`).
* **Packet-Level Threat Detection (Fast Path):**
    * **DPI (Deep Packet Inspection):** Performs basic checks for malicious DNS queries (against a blocklist), suspicious HTTP payloads, and known malware signatures.
    * **Heuristic Detection:** Identifies DoS (SYN Flood) attacks and Port Scans in real-time as they happen.
* **Complete GUI:** A multi-threaded Tkinter application to visualize:
    * Live statistics (packets/sec, data transferred, active flows).
    * A real-time log of security alerts from all detection methods.
    * Charts for threat distribution and protocol usage.
* **Built-in Network Tools:**
    * **Packet Analyzer:** View live packet summaries with a BPF filter and **save captures to a .pcap file** for analysis in Wireshark.
    * **Port Scanner:** Scan any IP address for open ports.
    * **Bandwidth Monitor:** See real-time graphs of your network usage.
* **Advanced Dashboards:**
    * **ML Dashboard:** Shows the status of the loaded pre-trained Random Forest model and its statistics.
    * **Firewall Manager:** View and manage IPs automatically blocked by the system.
    * **Threat Intelligence:** View a summary of detected threat IPs.

## How It Works

This application operates on a hybrid model:

1.  **Packet-Level (Real-time):**
    * A sniffing thread captures all IP packets using Scapy.
    * Each packet is immediately checked by `monitor.py` for:
        * Firewall block rules.
        * Simple heuristic threats (DoS, Port Scan).
        * Basic DPI signatures (malicious DNS, bad HTTP patterns).
    * If a packet-level threat is found, an alert is generated instantly.

2.  **Flow-Level (ML Analysis):**
    * Packets that are not blocked are passed to a flow assembler.
    * The `flow.py` module groups packets into "flows" based on their source/destination IP, port, and protocol.
    * When a flow ends (either by a FIN/RST packet or by timing out after 60 seconds), the `flow.py` module calculates its 78+ features.
    * These flow features are sent to the `ml_engine.py` module.
    * The `ml_engine.py` module uses the pre-loaded `rf_scaler.joblib` to scale the features and the `rf_model.joblib` (Random Forest) to predict the flow's class.
    * If the flow is classified as an attack (e.g., `FTP-Patator`), an `ML_...` alert is generated.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-github-repo-link>
    cd Realtime-Network-threat-detection
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv .venv
    # On Windows
    .\.venv\Scripts\Activate.ps1
    ```

3.  **Install dependencies:**
    (Ensure you have `joblib`, `pandas`, `scikit-learn`, `scapy`, and `matplotlib` in your `requirements.txt` file)
    ```bash
    pip install -r requirements.txt
    ```

## How to Train Your Own Model

This project relies on four files you must generate by training on a dataset:
* `rf_model.joblib`: The trained Random Forest model.
* `rf_scaler.joblib`: The scaler used on the training data.
* `rf_feature_names.joblib`: The exact list of feature names used.
* `rf_classes.joblib`: The names of the classes the model can predict.

A training script is provided in the `training/` folder.

1.  **Download a Dataset:** Get a flow-based dataset like CIC-IDS-2017 or CIC-IDS-2018. Place the `.csv` files (e.g., `Tuesday-WorkingHours.pcap_ISCX.csv`) into the `training/` folder.
2.  **Edit the Training Script:** Open `training/train_random_forest.py`.
    * Update `DATASET_FILENAME` to the CSV you want to use (e.g., `Tuesday...` which contains attacks).
    * **Crucially**, update the `feature_names_original` and `LABEL_COLUMN_ORIGINAL` lists to **exactly match** the column headers in your CSV file (check for spaces!).
    * Adjust `MAX_CHUNKS_TO_PROCESS` to control how much data you train on (to manage memory usage).
3.  **Run the Script:**
    ```bash
    # Navigate into the training folder
    cd training
    # Run the script
    python train_random_forest.py
    ```
4.  This will create the four new `.joblib` files in the main project directory, which the application will automatically load the next time it starts.

## How to Run the Application

You **must** run this application with **Administrator/Root privileges** to allow for packet capture.

1.  **Open PowerShell as Administrator.**
2.  Navigate to the project directory:
    ```powershell
    cd D:\cyber_security_tool\Realtime-Network-threat-detection
    ```
3.  Activate your virtual environment:
    ```powershell
    .\.venv\Scripts\Activate.ps1
    ```
4.  Run the main script:
    ```powershell
    python main.py
    ```
5.  Enter an IP to monitor (e.g., your router's IP `192.168.0.1`) and click "Start Monitoring".