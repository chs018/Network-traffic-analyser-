# 🛡️ Network Traffic Analysis and Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35.0-red?logo=streamlit)](https://streamlit.io/)
[![SQLite](https://img.shields.io/badge/SQLite-3-blue?logo=sqlite)](https://www.sqlite.org/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.5.0-orange?logo=scikit-learn)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Phase](https://img.shields.io/badge/Phase-1%20Foundation-brightgreen)](#roadmap)

> **Final Year Computer Networks Project**
> A production-quality, modular network traffic analysis and intrusion detection system featuring real-time packet capture, ML-powered anomaly detection, multi-attack classification, and an interactive Streamlit dashboard.

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Objectives](#objectives)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Folder Structure](#folder-structure)
- [Installation](#installation)
- [Running the Dashboard](#running-the-dashboard)
- [Configuration](#configuration)
- [Database Schema](#database-schema)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## 🌐 Project Overview

The **Network Traffic Analysis and Intrusion Detection System (NetTraffic IDS)** is designed to provide network administrators and security researchers with a comprehensive, real-time visibility and threat-detection platform.

The system captures raw network packets, parses them into structured records, analyses traffic patterns for anomalies and known attack signatures, and surfaces results through an interactive Streamlit dashboard. A scikit-learn–based machine learning pipeline provides anomaly scores and multi-class attack classification.

This repository represents **Phase 1** of a four-phase development plan: the complete project foundation, module architecture, database schema, and production-ready scaffolding are established here so that each subsequent phase (capture, detection, ML, polish) can be added without structural refactoring.

---

## 🎯 Objectives

| # | Objective | Phase |
|---|-----------|-------|
| 1 | Design modular, OOP-based architecture with clean separation of concerns | ✅ 1 |
| 2 | Implement SQLite-backed storage with typed schemas and indexes | ✅ 1 |
| 3 | Capture live network traffic using Scapy / PyShark | ✅ 2 |
| 4 | Detect DDoS, Port Scanning, and Brute-Force attacks via heuristic rules | ✅ 2 |
| 5 | Engineer ML features from traffic flows | ✅ 2 |
| 6 | Train Isolation Forest (anomaly) and Random Forest (classification) models | ✅ 3 |
| 7 | Deploy an interactive Streamlit dashboard with live charts and alerts | ✅ 2–3 |
| 8 | Generate downloadable PDF reports from analysis results | ✅ 3 |
| 9 | Deploy to Streamlit Community Cloud / Production Ready | ✅ 4 |

---

## ✨ Features

### Phase 1 (Current)
- ✅ **Modular architecture** — each concern lives in its own package with clean interfaces
- ✅ **Centralised configuration** — all constants, paths, thresholds, and ML hyperparameters in `utils/config.py`
- ✅ **Production logging** — coloured console + rotating file logging with per-module named loggers
- ✅ **SQLite schema** — normalised tables for traffic records, alerts, sessions, and ML model metadata
- ✅ **Type-safe codebase** — full PEP 484 type hints and dataclass-based data models
- ✅ **Streamlit entry point** — working dashboard with navigation, status page, and health checks
- ✅ **OOP detector base class** — `BaseDetector` ABC with pluggable Strategy pattern

### Phase 2 (Planned)
- 🔜 Live packet capture from network interfaces (Scapy / PyShark)
- 🔜 PCAP file replay for offline analysis
- 🔜 Real-time traffic charts (PPS, BPS, protocol pie)
- 🔜 DDoS rate-based detection with SYN-flood fingerprinting
- 🔜 Port scan detection (horizontal, vertical, stealth, NULL/FIN/XMAS)
- 🔜 Brute-force detection for SSH, RDP, FTP, HTTP

### Phase 3 (Planned)
- 🔜 Isolation Forest anomaly detector (unsupervised)
- 🔜 Random Forest attack classifier (5-class supervised)
- 🔜 Feature engineering pipeline with scaler + label encoder
- 🔜 PDF report generation with embedded charts
- 🔜 Alert acknowledgement workflow

### Phase 4 (Planned)
- 🔜 Streamlit Community Cloud deployment
- 🔜 PCAP dataset support (CIC-IDS-2017, UNSW-NB15)
- 🔜 Threat intelligence feed integration
- 🔜 Email/webhook alert notifications

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                        Streamlit Dashboard                     │
│   Home │ Traffic Analysis │ Attacks │ Alerts │ Reports         │
└────────────────────────────┬──────────────────────────────────┘
                             │
          ┌──────────────────▼──────────────────┐
          │           app.py (Entry Point)       │
          │  Page routing · Init · Health checks │
          └──────────┬───────────────────────────┘
                     │
     ┌───────────────┼──────────────────────┐
     │               │                      │
┌────▼─────┐  ┌──────▼──────┐   ┌──────────▼──────────┐
│ capture/ │  │  analysis/  │   │    detection/         │
│──────────│  │─────────────│   │──────────────────────│
│PcapReader│  │TrafficStats │   │ RuleEngine (BaseDetec)│
│PacketPars│  │ProtocolAnly │   │ DDoSDetector          │
│FeatureExt│  │BandwidthMon │   │ PortScanDetector       │
└────┬─────┘  │BottleneckDet│   │ BruteForceDetector     │
     │        └──────┬──────┘   └──────────┬────────────┘
     │               │                     │
     │        ┌──────▼──────────────────────▼─────────────┐
     │        │              ml/ (Phase 2+)                │
     │        │  DataPreprocessor · AnomalyDetector        │
     │        │  AttackClassifier · train_model            │
     │        └──────────────────────────────────────────┘
     │
┌────▼──────────────────────────────────────────────────────┐
│                     database/                              │
│   DatabaseManager · TrafficRecord · AlertRecord           │
│   SessionRecord · ModelMetadata · SQLite (traffic.db)     │
└────────────────────────────────────────────────────────────┘
     │
┌────▼──────────────────────────────────────────────────────┐
│                      utils/                                │
│   Config · Logger · Helpers                               │
└────────────────────────────────────────────────────────────┘
```

### Design Patterns Used

| Pattern | Location | Purpose |
|---------|----------|---------|
| **Singleton** | `utils/config.py` → `config` | One shared config instance |
| **Abstract Factory / ABC** | `detection/rule_engine.py` → `BaseDetector` | Pluggable detectors |
| **Strategy** | All `*Detector` subclasses | Swap detection algorithms |
| **Context Manager** | `DatabaseManager.__enter__` | Safe DB connection lifecycle |
| **Observer / Event Bus** | `RuleEngine.register()` | Fan-out traffic to detectors |
| **Repository** | `DatabaseManager` | Typed CRUD over SQLite |

---

## 🛠️ Tech Stack

| Category | Technology | Version | Purpose |
|----------|-----------|---------|---------|
| Language | Python | 3.11+ | Core runtime |
| Dashboard | Streamlit | 1.35.0 | Interactive web UI |
| Data | Pandas | 2.2.2 | DataFrame operations |
| Numerics | NumPy | 1.26.4 | Numerical computing |
| ML | Scikit-Learn | 1.5.0 | Anomaly detection & classification |
| Capture | Scapy | 2.5.0 | Packet crafting & capture |
| Capture | PyShark | 0.6 | TShark wrapper for PCAP |
| Charts | Plotly | 5.22.0 | Interactive visualisations |
| Database | SQLite 3 | built-in | Local persistent storage |
| PDF | ReportLab | 4.2.0 | PDF report generation |
| Validation | Pydantic | 2.7.1 | Data model validation |

---

## 📁 Folder Structure

```
network_traffic_analyzer/
│
├── app.py                        ← Streamlit entry point
├── requirements.txt              ← Python dependencies
├── README.md                     ← This file
│
├── data/
│   ├── raw/                      ← Original PCAP files
│   ├── processed/                ← Cleaned DataFrames (CSV/Parquet)
│   └── reports/                  ← Report data snapshots
│
├── database/
│   ├── db_manager.py             ← SQLite connection manager + CRUD
│   └── traffic.db                ← SQLite database (auto-created)
│
├── capture/
│   ├── __init__.py
│   ├── pcap_reader.py            ← PCAP file + live interface reader
│   ├── packet_parser.py          ← Raw packet → TrafficRecord
│   └── feature_extractor.py     ← TrafficRecord → ML FeatureVector
│
├── analysis/
│   ├── __init__.py
│   ├── traffic_statistics.py     ← Aggregate stats (PPS, BPS, top-N)
│   ├── protocol_analysis.py      ← Protocol distribution & anomalies
│   ├── bandwidth_monitor.py      ← Real-time BW utilisation tracking
│   └── bottleneck_detector.py    ← Congestion & elephant flow detection
│
├── detection/
│   ├── __init__.py
│   ├── rule_engine.py            ← BaseDetector ABC + orchestrator
│   ├── ddos_detector.py          ← DDoS heuristic detector
│   ├── portscan_detector.py      ← Port scan detector
│   └── bruteforce_detector.py    ← Brute-force login detector
│
├── ml/
│   ├── __init__.py
│   ├── preprocessing.py          ← Feature scaling, encoding, splitting
│   ├── train_model.py            ← Model training pipeline
│   ├── anomaly_detector.py       ← Isolation Forest wrapper
│   └── attack_classifier.py     ← Random Forest classifier wrapper
│
├── dashboard/
│   ├── __init__.py
│   ├── home.py                   ← KPI cards + system status
│   ├── traffic_page.py           ← Live traffic charts
│   ├── attack_page.py            ← Attack detection timeline
│   ├── alerts_page.py            ← Alert management
│   └── report_page.py            ← PDF report generation UI
│
├── reports/
│   ├── pdf_generator.py          ← ReportLab PDF builder
│   └── report_templates.py      ← Styles, colours, table formats
│
├── utils/
│   ├── __init__.py
│   ├── config.py                 ← All project constants & settings
│   ├── logger.py                 ← Centralised logging factory
│   └── helpers.py                ← IP, port, byte-format utilities
│
├── models/                       ← Serialised ML models (.pkl)
└── logs/                         ← Rotating log files (auto-created)
```

---

## ⚙️ Installation

### Prerequisites

- **Python 3.11 or higher** — [Download](https://www.python.org/downloads/)
- **Git** — [Download](https://git-scm.com/)
- **Npcap** (Windows) or **libpcap** (Linux/macOS) for live packet capture

### Step 1 — Clone the Repository

```bash
git clone https://github.com/<your-username>/network_traffic_analyzer.git
cd network_traffic_analyzer
```

### Step 2 — Create a Virtual Environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **Note for Windows users:** Live packet capture with Scapy requires [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" enabled. Install it before running any capture features.

### Step 4 — Verify Installation

```bash
python -c "import streamlit, pandas, numpy, sklearn, scapy; print('All core imports OK')"
```

---

## 🚀 Running the Dashboard

```bash
streamlit run app.py
```

The dashboard will open automatically at **http://localhost:8501**.

On first run, the app will:
1. Create all required directories (`data/`, `models/`, `logs/`, etc.)
2. Initialise the SQLite database (`database/traffic.db`)
3. Display the Phase 1 status page confirming all components are ready

---

## 🔧 Configuration

All project settings live in `utils/config.py`. Override any default by subclassing or patching the relevant dataclass:

```python
from utils.config import config

# Access detection thresholds
threshold = config.thresholds.ddos_packets_per_second   # 1000

# Access paths
db_path = config.paths.database_path   # .../database/traffic.db

# Access ML hyperparameters
n_estimators = config.ml.rf_n_estimators   # 100
```

Environment variables can be read via `config.get_env("MY_VAR", default="")`.

---

## 🗄️ Database Schema

The system uses four SQLite tables:

### `traffic_records`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-assigned |
| `timestamp` | TEXT | ISO-8601 capture time |
| `src_ip` / `dst_ip` | TEXT | Source / destination IP |
| `src_port` / `dst_port` | INTEGER | Port numbers |
| `protocol` | TEXT | TCP / UDP / ICMP / … |
| `packet_length` | INTEGER | Total packet bytes |
| `tcp_flags` | TEXT | Hex flag string |
| `label` | TEXT | BENIGN / DDoS / PortScan / … |
| `anomaly_score` | REAL | ML anomaly score (Phase 2) |

### `alerts`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-assigned |
| `alert_type` | TEXT | DDoS / PortScan / BruteForce |
| `severity` | TEXT | LOW / MEDIUM / HIGH / CRITICAL |
| `src_ip` / `dst_ip` | TEXT | IPs involved |
| `description` | TEXT | Human-readable summary |
| `is_acknowledged` | INTEGER | 0 or 1 |
| `raw_evidence` | TEXT | JSON evidence blob |

### `capture_sessions`
Tracks each capture session with aggregate statistics (total packets, bytes, alerts).

### `model_metadata`
Stores trained ML model paths, accuracy metrics, and active-model flags for Phase 2+.

---

## 🗺️ Roadmap

```
Phase 1 ✅  Foundation, architecture, DB schema, logging, config, app scaffold
Phase 2 ✅  Packet capture, parsing, traffic stats, heuristic attack detection
Phase 3 ✅  ML training (Isolation Forest + Random Forest), PDF reports
Phase 4 ✅  Enterprise SOC Dashboard, health monitor, live alerts, optimization
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/phase2-capture`)
3. Commit your changes following [Conventional Commits](https://www.conventionalcommits.org/)
4. Push to the branch (`git push origin feature/phase2-capture`)
5. Open a Pull Request

Please ensure all code passes `flake8` and `mypy` before submitting.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Network Traffic Analysis and Intrusion Detection System**
Final Year Computer Networks Project | Python 3.11+ | Streamlit | SQLite | Scikit-Learn

</div>
