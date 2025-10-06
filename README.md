# Realtime-Network-threat-detection
# Advanced Cyber Security Monitor

An educational tool for real-time network traffic analysis and threat detection, built with Python and Tkinter.

## ✨ Features

- **Real-Time Monitoring:** Captures and analyzes network packets on a target IP.
- **Threat Detection:** Basic detection for DoS floods and Port Scans.
- **Data Visualization:** Live-updating charts for threat and protocol distribution.
- **Built-in Tools:**
  - **Packet Analyzer:** Capture and inspect live network traffic with custom filters.
  - **Port Scanner:** Scan a target IP for open TCP ports.
- **Integrated Terminal:** Run common network commands (`ping`, `netstat`, `ipconfig`/`ifconfig`) directly within the app.

## 🚀 Setup and Run

### Prerequisites
- Python 3.8+
- Git

### Installation
1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
    cd your-repository-name
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application
This tool requires **administrator/root privileges** to capture network packets.

-   **On Windows:** Open PowerShell or Command Prompt **as Administrator** and run:
    ```bash
    python main.py
    ```

-   **On Linux/macOS:** Use `sudo`:
    ```bash
    sudo python main.py
    ```