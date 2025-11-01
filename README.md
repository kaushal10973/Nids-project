🛡️ Network Intrusion Detection System (NIDS)
A comprehensive Python-based Network Intrusion Detection System with real-time packet capture, machine learning-based threat classification, and automated response capabilities.
Show Image
Show Image
Show Image
Show Image
📋 Table of Contents

Features
Architecture
Installation
Configuration
Usage
Model Training
API Documentation
Testing
Deployment
Security Considerations
Troubleshooting
Contributing

✨ Features
Core Capabilities

Real-Time Packet Capture: Live network traffic monitoring using Scapy
ML-Based Detection: Random Forest and ensemble classifiers trained on NSL-KDD dataset
Multi-Category Attack Detection: DoS, Probe, R2L, U2R attacks
Automated Response: Configurable IP blocking and alerting
Web Dashboard: Real-time monitoring, historical log queries, statistics
Persistent Storage: SQLite database for alerts and flow data
RESTful API: Programmatic access to alerts and metrics

Attack Types Detected

DoS (Denial of Service): SYN flood, UDP flood, ICMP flood, etc.
Probe: Port scans, network mapping, vulnerability scanning
R2L (Remote to Local): Unauthorized access attempts, password guessing
U2R (User to Root): Privilege escalation, buffer overflow

🏗️ Architecture
┌─────────────────────────────────────────────────────────────┐
│                     NIDS Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────┐   │
│  │   Network    │─────▶│   Packet     │─────▶│ Feature │   │
│  │   Traffic    │      │   Sniffer    │      │ Extract  │   │
│  └──────────────┘      └──────────────┘      └──────────┘   │
│                                                      │      │
│                                                      ▼      │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────┐   │
│  │   Response   │◀─────│     ML       │◀─────│  Models │   │
│  │   Engine     │      │  Classifier  │      │  (RF/Ens)│   │
│  └──────────────┘      └──────────────┘      └──────────┘   │
│         │                      │                            │
│         │                      ▼                            │
│         │              ┌──────────────┐                     │
│         └────────────▶│   Database    │                    │
│                        │   (SQLite)   │                     │
│                        └──────────────┘                     │
│                               │                             │
│                               ▼                             │
│                        ┌──────────────┐                     │
│                        │    Flask     │                     │
│                        │  Dashboard   │                     │
│                        └──────────────┘                     │
└─────────────────────────────────────────────────────────────┘
🚀 Installation
Prerequisites

Python 3.10 or higher
Linux system with network access
Root/sudo privileges for packet capture
libpcap development files

Step 1: Install System Dependencies
bash# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-pip python3-dev libpcap-dev tcpdump

# RHEL/CentOS
sudo yum install python3-pip python3-devel libpcap-devel tcpdump

# macOS
brew install libpcap
Step 2: Clone Repository
bashgit clone https://github.com/yourusername/nids-project.git
cd nids-project
Step 3: Create Virtual Environment
bashpython3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Step 4: Install Python Dependencies
bashpip install -r requirements.txt
Step 5: Initialize Database
bashpython init_db.py
Step 6: Train/Load ML Models
bash# Option 1: Train on NSL-KDD dataset (recommended)
# First, download NSL-KDD dataset to data/nsl_kdd/
python train_models.py

# Option 2: Use dummy models for testing
# Models will be created automatically if NSL-KDD is not found
⚙️ Configuration
Edit config.yaml to customize NIDS behavior:
yamlnetwork:
  interface: "eth0"        # Network interface to monitor
  filter: "tcp or udp"     # BPF filter expression
  packet_count: 0          # 0 = unlimited

database:
  path: "nids.db"

ml_models:
  random_forest: "models/model_rf.pkl"
  ensemble: "models/model_ensemble.pkl"

dashboard:
  host: "0.0.0.0"
  port: 5000
  debug: false

response:
  auto_block: true         # Enable automatic IP blocking
  notification_enabled: true
  alert_threshold: 0.7     # Minimum confidence for action
  email: "admin@example.com"

logging:
  level: "INFO"            # DEBUG, INFO, WARNING, ERROR
  file: "nids.log"
🎯 Usage
Starting the NIDS
bash# Run with sudo for packet capture privileges
sudo python run.py
Accessing the Dashboard
Open your browser and navigate to:
http://localhost:5000
Dashboard Features

Home Dashboard (/)

Real-time alert statistics
Recent attack attempts
Traffic classification breakdown
Top attacking IPs


Logs Page (/logs)

Historical alert queries
Advanced filtering (IP, date, attack type)
Pagination support
Export capabilities


Settings Page (/settings)

View current configuration
System status
Model information



Command Line Options
bash# Specify custom config file
python run.py --config custom_config.yaml

# Test mode (no actual blocking)
python run.py --test-mode

# Verbose logging
python run.py --verbose
🤖 Model Training
Obtaining NSL-KDD Dataset

Download from: https://www.unb.ca/cic/datasets/nsl.html
Extract files to data/nsl_kdd/:

KDDTrain+.txt
KDDTest+.txt



Training Process
bashpython train_models.py
The script will:

Load and preprocess NSL-KDD data
Encode categorical features
Train Random Forest classifier (100 trees)
Train ensemble model (RF + Decision Tree)
Evaluate on test set
Save models to models/ directory
