# 🛡️ CyberGuard IDS & Host Firewall Engine

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-green?logo=node.js)
![Socket.IO](https://img.shields.io/badge/Socket.IO-Realtime-black?logo=socketdotio)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

A lightweight, real-time Host-based Intrusion Detection & Prevention System (HIDS/IPS) built using **Python (Scapy)** for packet sniffing and automated network defense, paired with an interactive **Node.js (Express + Socket.IO)** dashboard for live visual traffic analysis.

---

## 📸 Dashboard Showcase

### 1. Automated Port Scan Detection & Mitigation
Automatically identifies rapid multi-port probes across TCP/UDP layers and triggers immediate inbound firewall blocks.

![Port Scan Detection](screenshots/port-scan-alert.png)

### 2. High-Rate DDoS Flood Mitigation & Live Telemetry
Inspects Layer 3/Layer 4 frames in real-time. Attacks exceeding rate thresholds are actively dropped while allowing legitimate host traffic.

![DDoS Mitigation](screenshots/ddos-mitigation.png)

---

## ⚡ Key Features

- **Real-Time Packet Sniffing:** Low-level L3/L4 frame inspection via Scapy.
- **Automated Threat Detection:**
  - **DDoS/Flood Protection:** Flags and drops source IPs exceeding rate thresholds (`20 pkts/sec`).
  - **Port Scanning Defense:** Identifies horizontal/vertical scans across multiple target ports (`>4 ports in 3s`).
- **Active Firewall Enforcement:**
  - Automated kernel/OS-level blocking via Windows Defender Firewall (`netsh`) / Linux (`iptables`).
- **Live WebSocket Dashboard:** Real-time metrics streaming with active drop counts, packet logs, and telemetry.
- **Bi-directional IPC & Dashboard Control:** Allows operators to unblock false positives directly from the UI with zero manual CLI intervention.
- **Self-Cleaning Memory Management:** Thread-safe cleanup prevents memory leaks from inactive connection tracking.

---

## 🏗️ System Architecture

```text
       [ Inbound Network Traffic ]
                    │
                    ▼
          ┌───────────────────┐
          │   Python Engine   │  <── Scapy L3 Packet Sniffer
          └─────────┬─────────┘
                    │
         ┌──────────┴──────────┐
         │                     │
    (Threat Detected)    (Clean Traffic)
         │                     │
         ▼                     ▼
┌──────────────────┐  ┌───────────────────┐
│ Host Firewall    │  │ Async Event Queue │
│ (netsh/iptables) │  └─────────┬─────────┘
└──────────────────┘            │
                                ▼
                       ┌─────────────────┐
                       │ Node.js Server  │
                       └────────┬────────┘
                                │ (Socket.IO)
                                ▼
                       ┌─────────────────┐
                       │ Web Dashboard   │
                       └─────────────────┘

🚀 Getting Started
Prerequisites
Python 3.10+

Node.js 18+

Npcap (Windows users only): Ensure "WinPcap API-compatible Mode" is checked during installation.

Installation
Clone the Repository:

Bash
git clone [https://github.com/](https://github.com/)<your-username>/cyberguard-ids-firewall.git
cd cyberguard-ids-firewall
Setup the Dashboard:

Bash
cd dashboard
npm install
npm start
Dashboard will be available at: http://localhost:3000

Run the Security Engine:
Open a separate terminal with Administrator/Root privileges:

Bash
cd engine
pip install -r requirements.txt
python firewall.py
🔒 Configuration
Adjust thresholds directly inside engine/firewall.py:

Python
PACKET_LIMIT = 20         # Max allowable packets per time window
TIME_WINDOW = 1.0         # Time window in seconds for flood rate
SCAN_PORT_LIMIT = 4       # Max unique ports probed before trigger
SCAN_TIME_WINDOW = 3.0    # Scan observation window
⚠️ Disclaimer
This project is developed for educational and experimental purposes to demonstrate host-level intrusion detection and dynamic firewall automation. Always test in isolated environments before deployment.                       